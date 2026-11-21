"""How the cable runs (2026-11-21, David: "Don't run any electrical through cement slabs, all get routed from basement
ceiling" and "I like the user setting defaults for routing wires"): the routing options, the slab rule, the basement
ceiling, outlets through the studs, and the user's saved defaults. Small drawings built with ezdxf - never live plans."""
import pytest

ezdxf = pytest.importorskip("ezdxf")
from estimator.context import personal_context  # noqa: E402
from estimator.errors import InvalidInput  # noqa: E402
from estimator.takeoff import wiring, wiring_run  # noqa: E402
from test_wiring import _panel, _plan  # noqa: E402
from test_wiring_run import _job  # noqa: E402

CTX = personal_context()


def _circuits(tmp_path, **s):
    return {c["id"]: c for c in wiring.takeoff(_plan(tmp_path), _panel(tmp_path), s)["circuits"]}


def _total(tmp_path, **s):
    return sum(b["measured_ft"] for b in wiring.takeoff(_plan(tmp_path), _panel(tmp_path), s)["bom"])


def test_basement_runs_come_from_the_basement_ceiling(tmp_path):                         # RT-01
    c = _circuits(tmp_path)                                               # built in: a basement, panel in it
    assert c["C-1"]["home_run_ft"] == pytest.approx(8 + 0.5 - 5)          # panel up to the basement ceiling
    away = _circuits(tmp_path, panel_in_basement=False)                   # the panel on a ground-floor wall
    assert away["C-1"]["home_run_ft"] == pytest.approx(5 + 0.5)           # down the wall into the basement ceiling


def test_nothing_runs_in_a_slab(tmp_path):                                               # RT-02
    slab = _circuits(tmp_path, foundation="slab")
    assert slab["C-1"]["home_run_ft"] == pytest.approx(9 - 5)             # the panel up to the ceiling, not down
    # Asked to feed the outlets from below on a slab: they come from the ceiling instead - the same feet.
    assert _total(tmp_path, foundation="slab", outlets_via="below") == pytest.approx(
        _total(tmp_path, foundation="slab", outlets_via="above"))
    assert wiring.settings_with_defaults({"foundation": "slab"})["panel_in_basement"] is False
    assert "nothing in the slab" in wiring.routing_summary({"foundation": "slab"})


def test_outlets_through_the_studs_beat_up_and_over_the_ceiling(tmp_path):              # RT-03
    studs, ceiling = _circuits(tmp_path), _circuits(tmp_path, outlets_via="above")
    # Outlet to outlet through the studs: no climb to the ceiling and back at every box. (An outlet nearer the
    # basement-ceiling run than its neighbour is fed straight from below either way.)
    assert _total(tmp_path) < _total(tmp_path, outlets_via="above")
    assert sum(c["run_ft"] for c in studs.values()) < sum(c["run_ft"] for c in ceiling.values())
    # Lights always go through the ceiling: the outlets' choice doesn't touch a lighting circuit.
    assert studs["C-5"]["run_ft"] == ceiling["C-5"]["run_ft"]
    # A run longer than the wall limit (past a door, across a room) goes the feed way: more cable.
    assert _total(tmp_path, wall_max_ft=4) >= _total(tmp_path)


def test_box_heights_count(tmp_path):                                                    # RT-04
    lo, hi = _circuits(tmp_path, receptacle_in=12), _circuits(tmp_path, receptacle_in=24)
    assert lo["C-4"]["run_ft"] != hi["C-4"]["run_ft"]
    # Kitchen counter GFCI outlets sit at the counter height.
    d = wiring.Device("x", "duplex_receptacle_gfci", 0, 0, 0, room="KITCHEN")
    assert wiring._z(d, wiring.settings_with_defaults({})) == pytest.approx(44 / 12)


def test_options_are_checked():                                                          # RT-05
    with pytest.raises(InvalidInput, match="foundation"):
        wiring_run._settings({"foundation": "mud"})
    with pytest.raises(InvalidInput, match="outlets via"):
        wiring_run._settings({"outlets_via": "sky"})
    s = wiring_run._settings({"foundation": "slab", "outlets_via": "walls", "panel_in_basement": "false",
                              "waste": 0.12, "route": {"0": "auto", "1": "walls"}})
    assert s == {"foundation": "slab", "outlets_via": "walls", "panel_in_basement": False, "waste": 0.12,
                 "route": {1: "walls"}}


def test_saved_defaults_start_every_new_project(db, tmp_path):                          # RT-06
    p = wiring_run._defaults_path(CTX)
    try:
        assert wiring_run.options(CTX)["from"] == "built in"
        saved = wiring_run.save_defaults(CTX, {"foundation": "slab", "ceiling_ft": 8, "route": {"0": "walls"}})
        assert saved == {"foundation": "slab", "ceiling_ft": 8.0}             # a forced floor stays with its project
        est = _job(db, tmp_path)
        o = wiring_run.options(CTX, est["id"])
        assert o["from"] == "your defaults" and o["current"]["foundation"] == "slab" and o["current"]["ceiling_ft"] == 8
        r = wiring_run.run(db, CTX, est["id"])                                 # no settings given: the defaults
        assert r["settings"]["foundation"] == "slab" and r["settings"]["ceiling_ft"] == 8
        assert "slab" in r["routing"]
        # This project's run wins over the defaults from now on; a given setting wins over both.
        r = wiring_run.run(db, CTX, est["id"], {"foundation": "basement"})
        o = wiring_run.options(CTX, est["id"])
        assert o["from"] == "last run" and o["current"]["foundation"] == "basement" and o["current"]["ceiling_ft"] == 8
    finally:
        p.unlink(missing_ok=True)


def test_only_estimators_save_defaults():                                                # RT-07
    import dataclasses
    from estimator.errors import PermissionDenied
    viewer = dataclasses.replace(CTX, role="viewer")
    with pytest.raises(PermissionDenied):
        wiring_run.save_defaults(viewer, {"foundation": "slab"})
