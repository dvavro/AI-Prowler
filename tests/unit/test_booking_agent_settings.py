"""Booking & scheduling agent — settings and the booking-flow diagram (booking-agent-spec.md
Phase B0; David 2026-10-30 "yes for 1-5").
Run: run_tests.bat tests\\unit\\test_booking_agent_settings.py
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent_settings as das  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import desk_http as h  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402

ON = {"agent_enabled": True, "agent_bk_enabled": True, "agent_bk_shadow": False}


@pytest.fixture
def db(tmp_path):
    d = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(d)
    return d


def steps(model):
    return {p["id"]: p for p in model["steps"]}


def states(model):
    return {s["id"]: s for s in model["states"]}


def test_defaults_are_safe(db):
    s = desk_db.get_settings(db)
    assert s["agent_bk_enabled"] is False and s["agent_bk_shadow"] is True and s["agent_bk_can_confirm"] is False
    assert all(s[f"agent_bk_stage_{k}"] == "suggest" for k, _ in das.BK_STAGES)
    assert s["agent_bk_confirm_per_day"] == 5 and s["agent_bk_weather"] is True and s["agent_bk_check_hour"] == 16
    assert set(k for k in das.DEFAULTS if k.startswith("agent_bk_")) <= set(desk_tools.SETTING_HELP)


def test_settings_are_checked(db):
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(db, "agent_bk_stage_decide", "always", edition=r.SOLO)
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(db, "agent_bk_confirm_per_day", 0, edition=r.SOLO)
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(db, "agent_bk_check_hour", 24, edition=r.SOLO)
    desk_db.set_setting(db, "agent_bk_stage_decide", "auto", edition=r.SOLO)
    assert desk_db.get_settings(db)["agent_bk_stage_decide"] == "auto"


def test_off_means_nothing_runs_and_needs_the_main_switch():
    m = das.booking_flow({})
    assert all(p["mode"] == "inactive" for p in m["steps"]) and not any(s["lit"] for s in m["states"])
    assert "agent is off" in m["summary"]
    m = das.booking_flow({"agent_enabled": True})
    assert all(p["mode"] == "inactive" for p in m["steps"]) and "Booking & scheduling is off" in m["summary"]
    assert das.bk_stage_mode({"agent_bk_enabled": True}, "check") == "inactive"   # needs Agent on too


def test_each_step_is_coloured_by_its_own_choice():
    s = dict(ON, agent_bk_stage_check="auto", agent_bk_stage_decide="suggest", agent_bk_stage_learn="off")
    m = das.booking_flow(s)
    st = steps(m)
    assert st["check"]["color"] == das.MODE_COLORS["auto"] and st["check"]["word"] == "automatic"
    assert st["decide"]["color"] == das.MODE_COLORS["suggest"]
    assert st["learn"]["mode"] == "off"
    lit = states(m)
    assert lit["Requested"]["lit"] and lit["Requested"]["color"] == das.MODE_COLORS["auto"]     # Check works on it
    assert lit["To approve"]["color"] == das.MODE_COLORS["auto"]                                # strongest wins
    assert not lit["Done"]["lit"]                                                               # Learn is off
    assert "Does on its own: Check." in m["summary"] and "Off: Learn." in m["summary"]
    assert "A person always confirms bookings." in m["summary"]


def test_practice_rings_keep_the_choice_visible():
    m = das.booking_flow(dict(ON, agent_bk_shadow=True, agent_bk_stage_track="auto"))
    st = steps(m)
    assert st["track"]["practice"] and st["track"]["mode"] == "practice" and st["track"]["word"] == "automatic"
    assert m["summary"].startswith("Practice mode is ON") and m["practice"]


def test_confirming_needs_the_tick_auto_and_no_practice():
    s = dict(ON, agent_bk_can_confirm=True)
    assert not das.can_confirm(s)                                          # Decide still on Suggest
    assert "only works with Decide on Auto" in das.booking_flow(s)["summary"]
    s["agent_bk_stage_decide"] = "auto"
    assert das.can_confirm(s) and "may confirm bookings itself (at most 5 a day" in das.booking_flow(s)["summary"]
    assert not das.can_confirm(dict(s, agent_bk_shadow=True))             # practice: never
    assert not das.can_confirm(dict(s, agent_bk_can_confirm=False))


def test_the_diagram_fits_its_box():
    m = das.booking_flow(ON)
    for b in m["states"] + m["steps"]:
        assert 0 <= b["x"] and b["x"] + b["w"] <= m["w"] and 0 <= b["y"] and b["y"] + b["h"] <= m["h"]
    boxes = [(b["x"], b["y"], b["x"] + b["w"], b["y"] + b["h"]) for b in m["states"] + m["steps"]]
    for i, a in enumerate(boxes):                                          # nothing overlaps
        for b in boxes[i + 1:]:
            assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1], (a, b)


def test_ticket_diagram_unchanged_by_the_refactor():
    m = das.flow({"agent_enabled": True, "agent_shadow": False, "agent_stage_intake": "auto"}, "solo")
    assert {s["id"] for s in m["states"]} == {"Open", "Assigned", "In Progress", "Fixed", "Closed", "On Hold"}
    assert states(m)["Assigned"]["label"] == "Assigned (you)" and states(m)["Open"]["lit"]
    assert "Solo: every ticket stays yours" in steps(m)["intake"]["help"]


def test_ai_prowler_saves_the_booking_section(db):
    form = {"agent_bk_enabled": True, "agent_bk_shadow": False, "agent_bk_can_confirm": True, "agent_bk_weather": False,
            "agent_bk_confirm_per_day": "3", "agent_bk_check_hour": "15", "agent_bk_stage_decide": "auto"}
    ok, msg = dga.save(db, form, edition=r.SOLO)
    s = desk_db.get_settings(db)
    assert ok and s["agent_bk_enabled"] and s["agent_bk_confirm_per_day"] == 3 and s["agent_bk_check_hour"] == 15
    assert s["agent_bk_stage_decide"] == "auto" and not s["agent_bk_weather"]
    ok, msg = dga.save(db, {"agent_bk_confirm_per_day": "lots"}, edition=r.SOLO)
    assert not ok and "whole number" in msg


def test_the_app_gets_the_booking_section(db):
    st, ct, out = h.route("GET", "/desk-api/agent", query={}, body=b"", content_type="", actor=None,
                          edition=r.SOLO, db_path=db, services={})
    d = json.loads(out)
    assert st == 200 and [k for k, _ in d["bk_options"]["stages"]] == [k for k, _ in das.BK_STAGES]
    assert d["bk_flow"]["states"] and "confirm_help" in d["bk_options"]
    html = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    assert "renderAgentFlow(d.bk_flow, 'bkFlow', 'booking')" in html and 'data-agb="agent_bk_can_confirm"' in html


def test_outdoor_flag_on_services(tmp_path):
    import booking_db as bdb
    from db_access import get_connection, init_db
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    c = get_connection(jobs)
    c.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('WIN-EXT', 'Exterior windows', 150)")
    c.close()
    bdb.sync_services(jobs)
    assert bdb.list_services(jobs)[0]["outdoor"] is False
    assert bdb.update_service(jobs, "WIN-EXT", outdoor=True)["outdoor"] is True
