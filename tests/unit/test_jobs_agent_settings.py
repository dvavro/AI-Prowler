"""Jobs agent J0 (jobs-agent-spec.md; David 2026-10-31): its settings in their own agent
database, the 8 stages, the invoice switch, reminder days, and the jobs-flow diagram coloured
like the ticket one. Run: run_tests.bat tests\\unit\\test_jobs_agent_settings.py
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent_settings as das  # noqa: E402
import desk_agent_store as store  # noqa: E402
import desk_db  # noqa: E402
import desk_jobs_agent as ja  # noqa: E402
import desk_http  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402

S = r.SOLO


@pytest.fixture
def agent_db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "PATH_OVERRIDE", tmp_path / "agent_database" / "agent.db")
    return str(tmp_path / "agent_database" / "agent.db")


def test_defaults_are_safe():
    s = {k: das.DEFAULTS[k] for k in das.JB_KEYS}
    assert s["agent_jb_enabled"] is False and s["agent_jb_shadow"] is True
    assert s["agent_jb_can_send_invoices"] is False                      # decision 1: off by default
    assert s["agent_jb_remind_days"] == [7, 14, 30]                       # decision 2
    assert s["agent_jb_stage_onsite"] == "auto"
    assert all(s[f"agent_jb_stage_{k}"] == "suggest" for k, _ in das.JB_STAGES if k != "onsite")
    assert len(das.JB_STAGES) == 8


def test_stage_mode_and_invoice_switch():
    s = {k: das.DEFAULTS[k] for k in das.JB_KEYS}
    assert das.jb_stage_mode(s, "schedule") == "inactive"
    s["agent_jb_enabled"] = True
    assert das.jb_stage_mode(s, "schedule") == "practice"
    s["agent_jb_shadow"] = False
    s["agent_jb_stage_closeout"] = "auto"
    assert not das.can_send_invoices(s)
    s["agent_jb_can_send_invoices"] = True
    assert das.can_send_invoices(s)
    s["agent_jb_stage_quotes"] = "off"
    assert das.jb_stage_mode(s, "quotes") == "off"


def test_store_keeps_its_own_settings(agent_db, tmp_path):
    assert Path(agent_db).exists() is False
    s = store.settings()
    assert Path(agent_db).exists() and s["agent_jb_enabled"] is False
    store.set_setting("agent_jb_enabled", True)
    store.set_setting("agent_jb_remind_days", [5, 10])
    assert store.settings()["agent_jb_enabled"] is True and store.settings()["agent_jb_remind_days"] == [5, 10]
    with pytest.raises(desk_db.DeskError):
        store.set_setting("agent_enabled", True)                          # not a Jobs agent setting
    for bad in ([30, 14], [0], [1, 2, 3, 4], [7, 7]):
        with pytest.raises(desk_db.DeskError):
            store.set_setting("agent_jb_remind_days", bad)
    with pytest.raises(desk_db.DeskError):
        store.set_setting("agent_jb_stage_quotes", "sometimes")
    # its tables are the shared engine's
    import desk_agent
    assert desk_agent.status(agent_db)["waiting"] == 0


def test_flow_colours_each_step_by_its_mode(agent_db):
    store.set_setting("agent_jb_enabled", True)
    store.set_setting("agent_jb_shadow", False)
    store.set_setting("agent_jb_stage_collect", "auto")
    store.set_setting("agent_jb_stage_repeat", "off")
    f = store.flow(S)
    steps = {p["id"]: p for p in f["steps"]}
    assert steps["collect"]["color"] == das.MODE_COLORS["auto"]
    assert steps["schedule"]["color"] == das.MODE_COLORS["suggest"]
    assert steps["repeat"]["mode"] == "off"
    states = {x["id"]: x for x in f["states"]}
    assert states["Invoiced"]["lit"] and states["Invoiced"]["color"] == das.MODE_COLORS["auto"]
    assert states["Unscheduled"]["color"] == das.MODE_COLORS["suggest"]
    assert "You send every invoice" in f["summary"] and "No payments" in f["summary"]
    assert [x[0] for x in f["legend"]] == ["auto", "suggest", "practice", "off"]
    # unsaved choices redraw without saving
    g = store.flow(S, overrides={"agent_jb_stage_repeat": "auto"})
    assert {p["id"]: p for p in g["steps"]}["repeat"]["color"] == das.MODE_COLORS["auto"]
    assert store.settings()["agent_jb_stage_repeat"] == "off"


def test_practice_rings_and_off_summary(agent_db):
    f = store.flow(S)
    assert "Jobs agent is off" in f["summary"]
    store.set_setting("agent_jb_enabled", True)
    f = store.flow(S)
    assert f["practice"] and all(p["practice"] for p in f["steps"])
    assert f["summary"].startswith("Practice mode is ON")


def test_diagram_fits_its_box_and_nothing_overlaps():
    f = das.jobs_flow({**{k: das.DEFAULTS[k] for k in das.JB_KEYS}, "agent_jb_enabled": True}, S)
    boxes = [(b["x"], b["y"], b["x"] + b["w"], b["y"] + b["h"]) for b in f["states"] + f["steps"]]
    for x1, y1, x2, y2 in boxes:
        assert 0 <= x1 and x2 <= f["w"] and -1 <= y1 and y2 <= f["h"]
    for i, a in enumerate(boxes):
        for b in boxes[i + 1:]:
            assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1], (a, b)
    names = {x["id"] for x in f["states"]}
    assert all(st in names for lst in das._JB_STEP_EDGES.values() for *_, st in lst)
    assert names == {"Quote", "Unscheduled", "Scheduled", "In Progress", "Complete", "Invoiced", "Paid"}


def test_route_flow_has_its_own_switches(agent_db):
    """David 2026-10-31: a separate enable and practice mode for the Route flow."""
    assert das.DEFAULTS["agent_jb_rt_enabled"] is False and das.DEFAULTS["agent_jb_rt_shadow"] is True
    assert {"agent_jb_rt_enabled", "agent_jb_rt_shadow"} <= set(das.JB_KEYS)
    store.set_setting("agent_jb_enabled", True)
    store.set_setting("agent_jb_shadow", False)
    s = store.settings()
    assert das.jb_stage_mode(s, "quotes") == "suggest"
    assert das.rt_stage_mode(s, "sort") == "inactive"                       # jobs on, routes still off
    assert all(p["mode"] == "inactive" for p in das.route_flow(s, S)["steps"])
    assert "Route flow is off" in das.route_flow(s, S)["summary"]
    store.set_setting("agent_jb_enabled", False)
    store.set_setting("agent_jb_rt_enabled", True)                          # routes on, jobs off
    s = store.settings()
    assert das.jb_stage_mode(s, "quotes") == "inactive"
    assert das.rt_stage_mode(s, "sort") == "practice"                       # its own practice default
    assert ja.mode("route", s, "sort") == "practice" and ja.mode(ja.JOB, s, "quotes") == "inactive"
    assert ja.enabled(s) and das.jb_any_on(s)
    store.set_setting("agent_jb_rt_shadow", False)
    store.set_setting("agent_jb_shadow", True)                              # jobs practice doesn't touch routes
    assert das.rt_stage_mode(store.settings(), "sort") == "suggest"
    store.set_setting("agent_jb_rt_enabled", False)
    assert not ja.enabled(store.settings())


def test_jobs_section_header_shows_both_saved_switches(agent_db):
    import desk_gui_agent as dga
    assert dga.agent_section_status("jobs")["text"] == "(jobs off · routes off)"
    store.set_setting("agent_jb_rt_enabled", True)                          # route practice is the default
    st = dga.agent_section_status("jobs")
    assert st["text"] == "(jobs off · routes on — practice mode)" and st["color"] == das.MODE_COLORS["practice"]
    store.set_setting("agent_jb_enabled", True)
    store.set_setting("agent_jb_shadow", False)
    st = dga.agent_section_status("jobs")
    assert st["text"] == "(jobs on · routes on — practice mode)" and st["color"] == das.MODE_COLORS["auto"]


def test_route_flow_follows_its_own_stages(agent_db):
    store.set_setting("agent_jb_rt_enabled", True)
    store.set_setting("agent_jb_rt_shadow", False)
    store.set_setting("agent_jb_rt_stage_sort", "auto")
    store.set_setting("agent_jb_rt_stage_replan", "off")
    store.set_setting("agent_jb_route_scope", "week")
    store.set_setting("agent_jb_sort_weekday", 6)
    f = store.flow(S, which="route")
    steps = {p["id"]: p for p in f["steps"]}
    assert [p["id"] for p in f["steps"]] == ["sort", "plan", "route", "send", "replan"]
    assert steps["sort"]["color"] == das.MODE_COLORS["auto"] and steps["replan"]["mode"] == "off"
    states = {x["id"]: x for x in f["states"]}
    assert states["Unscheduled"]["color"] == das.MODE_COLORS["auto"] and states["Crew has route"]["lit"]
    assert states["Crew has route"]["label"] == "Your route"                         # personal install
    assert das.route_flow(store.settings(), "business")["states"][-1]["label"] == "Crew's route"
    assert "Sundays" in f["summary"] and "the whole week at once" in f["summary"]
    assert "never moved" in f["summary"]
    with pytest.raises(desk_db.DeskError):
        store.set_setting("agent_jb_route_scope", "month")
    boxes = [(b["x"], b["y"], b["x"] + b["w"], b["y"] + b["h"]) for b in f["states"] + f["steps"]]
    for i, a in enumerate(boxes):
        assert 0 <= a[0] and a[2] <= f["w"] and a[3] <= f["h"]
        for b in boxes[i + 1:]:
            assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1], (a, b)
    assert all(st in states for lst in das._RT_STEP_EDGES.values() for *_, st in lst)


def test_gui_form_values(agent_db):
    import desk_gui_agent as g
    modes = [[m, das.STAGE_MODE_LABELS[m]] for m in das.STAGE_MODES]
    form = {"agent_jb_enabled": True, "agent_jb_shadow": False, "agent_jb_can_send_invoices": True,
            "agent_jb_weather": False, "agent_jb_invoice_max": "$1,500", "agent_jb_invoices_per_day": "4",
            "agent_jb_quote_days": "3", "agent_jb_prep_hour": "15", "agent_jb_remind_days": "10, 20, 45",
            **{f"agent_jb_stage_{k}": das.STAGE_MODE_LABELS["auto"] for k, _ in das.JB_STAGES}}
    ok, msg = g.save_jobs(form, modes, S)
    assert ok, msg
    s = store.settings()
    assert (s["agent_jb_invoice_max"], s["agent_jb_remind_days"], s["agent_jb_stage_learn"]) == (1500, [10, 20, 45], "auto")
    ok, msg = g.save_jobs(dict(form, agent_jb_remind_days="soon"), modes, S)
    assert not ok and "reminder days" in msg


def call(db, method, path, body=None):
    st, ct, out = desk_http.route(method, path, query={}, body=json.dumps(body or {}).encode(),
                                  content_type="application/json", actor=None, edition=S, db_path=db,
                                  services={"business": "Blue Wave"})
    return st, json.loads(out)


def test_app_card_reads_and_saves_the_agent_database(agent_db, tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    st, d = call(tickets, "GET", "/desk-api/agent")
    assert st == 200 and d["jb_options"]["stages"][0][0] == "quotes" and d["jb_flow"]["states"]
    st, d = call(tickets, "POST", "/desk-api/agent/jobs", {"settings": {"agent_jb_enabled": True,
                                                                       "agent_jb_stage_schedule": "auto"}})
    assert st == 200 and d["settings"]["agent_jb_enabled"] is True
    assert desk_db.get_settings(tickets).get("agent_jb_enabled") is False      # not in the Service Desk database
    st, d = call(tickets, "POST", "/desk-api/agent/jobs/flow", {"settings": {"agent_jb_stage_schedule": "off"}})
    assert {p["id"]: p for p in d["jb_flow"]["steps"]}["schedule"]["mode"] == "off"
    st, d = call(tickets, "POST", "/desk-api/agent/jobs", {"key": "agent_jb_remind_days", "value": [30, 7]})
    assert st == 400


def test_chat_settings_tool_routes_jobs_keys(agent_db, tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    out = desk_tools.tickets_settings(tickets, None, S, setting="agent_jb_enabled", value="on")
    assert "Saved" in out and store.settings()["agent_jb_enabled"] is True
    assert "agent_jb_enabled = on" in out
