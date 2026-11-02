"""HR agent H0 (hr-agent-spec.md; Vicki 2026-10-31): its settings in its own database inside the
HR data folder, the 9 stages, the three configurable decisions (approve time off, who reviews,
incident reports), the runner rule (API keys or the Claude CLI — never a chat), and the HR
diagram coloured like the others. Run: run_tests.bat tests\\unit\\test_hr_agent_settings.py
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent_hr_store as store  # noqa: E402
import desk_agent_settings as das  # noqa: E402
import desk_db  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402

B = r.BUSINESS


@pytest.fixture
def hr_db(tmp_path, monkeypatch):
    p = tmp_path / "hr" / "agent" / "hr_agent.db"
    monkeypatch.setattr(store, "PATH_OVERRIDE", p)
    return str(p)


def defaults():
    return {k: das.DEFAULTS[k] for k in das.HR_KEYS}


def test_defaults_are_safe():
    s = defaults()
    assert s["agent_hr_enabled"] is False and s["agent_hr_shadow"] is True
    assert s["agent_hr_can_approve_timeoff"] is False                      # decision 1: off until ticked
    assert s["agent_hr_reviewers"] == "hr_admin"                           # decision 2: HR only until widened
    assert s["agent_hr_incidents_access"] == "type_only"                   # decision 3: never reads until allowed
    assert s["agent_hr_stage_timeclock"] == "auto"                         # notes only
    assert all(s[f"agent_hr_stage_{k}"] == "suggest" for k, _ in das.HR_STAGES if k != "timeclock")
    assert len(das.HR_STAGES) == 9 and s["agent_hr_quiet_hours"] == [8, 18]


def test_stage_mode_and_time_off_switch():
    s = defaults()
    assert das.hr_stage_mode(s, "timeoff") == "inactive"
    s["agent_hr_enabled"] = True
    assert das.hr_stage_mode(s, "timeoff") == "practice"
    s.update(agent_hr_shadow=False, agent_hr_stage_timeoff="auto")
    assert not das.can_approve_timeoff(s)
    s["agent_hr_can_approve_timeoff"] = True
    assert das.can_approve_timeoff(s)
    s["agent_hr_shadow"] = True
    assert not das.can_approve_timeoff(s)                                  # practice never approves


def test_runner_is_api_keys_only_never_a_chat():
    for p in ("claude_api", "grok_api"):
        assert das.hr_runner({"agent_provider": p}, B) == (p, "")
    for ed in ("solo", B):                                                 # 2026-11-01: no Claude CLI anywhere
        p, why = das.hr_runner({"agent_provider": "claude_code"}, ed)
        assert p == "" and "Claude API key or the Grok bot" in why
    p, why = das.hr_runner({"agent_provider": "chat_only"}, "solo")
    assert p == "" and "never runs from a chat" in why and "Claude subscription" not in why
    assert "Muse" in das.HR_RUNNER_HELP and "CLI" not in das.HR_RUNNER_HELP


def test_store_lives_in_the_hr_data_folder_and_keeps_its_own_settings(hr_db, monkeypatch, tmp_path):
    assert not Path(hr_db).exists()
    s = store.settings()
    assert Path(hr_db).exists() and s["agent_hr_enabled"] is False
    store.set_setting("agent_hr_enabled", True)
    store.set_setting("agent_hr_reviewers", "hr_admin_managers")
    store.set_setting("agent_hr_incidents_access", "read")
    store.set_setting("agent_hr_expiry_days", [90, 14])
    s = store.settings()
    assert (s["agent_hr_enabled"], s["agent_hr_reviewers"], s["agent_hr_incidents_access"], s["agent_hr_expiry_days"]) \
        == (True, "hr_admin_managers", "read", [90, 14])
    for k, bad in (("agent_hr_reviewers", "everyone"), ("agent_hr_incidents_access", "summary"),
                   ("agent_hr_expiry_days", [7, 30]), ("agent_hr_expiry_days", [0]), ("agent_hr_quiet_hours", [18, 8]),
                   ("agent_hr_timeoff_max_days", 30), ("agent_hr_stage_answer", "sometimes")):
        with pytest.raises(desk_db.DeskError):
            store.set_setting(k, bad)
    with pytest.raises(desk_db.DeskError):
        store.set_setting("agent_jb_enabled", True)                        # not an HR agent setting
    # without an override it sits next to hr_db.json (the HR module's own folder)
    monkeypatch.setattr(store, "PATH_OVERRIDE", None)
    # 2026-11-02: in a full run an earlier test imports ai_prowler_mcp, which sets hr_root_fn to ITS HR
    # folder — clear it so this checks the plain fallback (it failed only in the full run)
    monkeypatch.setattr(store, "hr_root_fn", None)
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path / "sandbox"))
    assert Path(store.path()) == tmp_path / "sandbox" / "agent" / "hr_agent.db"
    monkeypatch.setattr(store, "hr_root_fn", lambda: str(tmp_path / "elsewhere"))
    assert Path(store.path()) == tmp_path / "elsewhere" / "agent" / "hr_agent.db"


def test_shared_runner_settings_are_copied(hr_db, tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    desk_db.set_setting(tickets, "agent_provider", "claude_api", edition=B)
    desk_db.set_setting(tickets, "agent_name", "Sam", edition=B)
    s = store.sync_shared(tickets)
    assert s["agent_provider"] == "claude_api" and s["agent_name"] == "Sam"
    assert desk_db.get_settings(tickets).get("agent_hr_enabled") is False   # HR settings never in Service Desk


def test_flow_colours_each_step_and_says_the_choices(hr_db):
    store.set_setting("agent_hr_enabled", True)
    store.set_setting("agent_hr_shadow", False)
    store.set_setting("agent_hr_stage_onboard", "auto")
    store.set_setting("agent_hr_stage_recruit", "off")
    f = store.flow(B, shared={"agent_provider": "claude_api"})
    steps = {p["id"]: p for p in f["steps"]}
    assert steps["onboard"]["color"] == das.MODE_COLORS["auto"]
    assert steps["timeoff"]["color"] == das.MODE_COLORS["suggest"] and steps["recruit"]["mode"] == "off"
    states = {x["id"]: x for x in f["states"]}
    assert states["Onboarding"]["lit"] and states["Onboarding"]["color"] == das.MODE_COLORS["auto"]
    assert not states["Candidate"]["lit"]
    assert "A person approves all time off" in f["summary"] and "type only" in f["summary"]
    assert "never changes pay" in f["summary"] and "⚠" not in f["summary"]
    # a chat runner is called out
    assert "never runs from a chat" in store.flow(B, shared={"agent_provider": "chat_only"})["summary"]
    g = store.flow(B, overrides={"agent_hr_incidents_access": "read", "agent_hr_reviewers": "hr_admin_managers"},
                   shared={"agent_provider": "grok_api"})
    assert "it reads them" in g["summary"] and "managers" in g["summary"]
    assert store.settings()["agent_hr_incidents_access"] == "type_only"   # overrides aren't saved


def test_off_and_practice(hr_db):
    assert "HR agent is off" in store.flow(B)["summary"]
    store.set_setting("agent_hr_enabled", True)
    f = store.flow(B)
    assert f["practice"] and all(p["practice"] for p in f["steps"] if p["chosen"] != "off")


def test_diagram_fits_its_box_and_nothing_overlaps():
    f = das.hr_flow({**defaults(), "agent_hr_enabled": True}, B)
    boxes = [(b["x"], b["y"], b["x"] + b["w"], b["y"] + b["h"]) for b in f["states"] + f["steps"]]
    for x1, y1, x2, y2 in boxes:
        assert 0 <= x1 and x2 <= f["w"] and -1 <= y1 and y2 <= f["h"]
    for i, a in enumerate(boxes):
        for b in boxes[i + 1:]:
            assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1], (a, b)
    names = {x["id"] for x in f["states"]}
    assert all(st in names for lst in das._HR_STEP_EDGES.values() for *_, st in lst)
    assert names == {"Candidate", "Hired", "Onboarding", "Active", "On leave", "Offboarding", "Former"}
    assert [p["id"] for p in f["steps"]] == [k for k in das._HR_STEPS]


def test_gui_form_values(hr_db):
    import desk_gui_agent as g
    modes = [[m, das.STAGE_MODE_LABELS[m]] for m in das.STAGE_MODES]
    form = {"agent_hr_enabled": True, "agent_hr_shadow": False, "agent_hr_can_approve_timeoff": True,
            "agent_hr_ack_sensitive": False, "agent_hr_timeoff_max_days": "3", "agent_hr_timeoff_notice_days": "7",
            "agent_hr_timeoff_max_off": "2", "agent_hr_timeoff_per_day": "4", "agent_hr_overtime_warn_hours": "38",
            "agent_hr_reviewers": dict(das.HR_REVIEWERS)["hr_admin_managers"],
            "agent_hr_incidents_access": dict(das.HR_INCIDENTS)["read"],
            "agent_hr_quiet_hours": "7-19", "agent_hr_expiry_days": "45, 10",
            **{f"agent_hr_stage_{k}": das.STAGE_MODE_LABELS["auto"] for k, _ in das.HR_STAGES}}
    ok, msg = g.save_hr(form, modes, B)
    assert ok, msg
    s = store.settings()
    assert (s["agent_hr_quiet_hours"], s["agent_hr_expiry_days"], s["agent_hr_reviewers"],
            s["agent_hr_incidents_access"], s["agent_hr_stage_learn"]) == ([7, 19], [45, 10], "hr_admin_managers",
                                                                           "read", "auto")
    ok, msg = g.save_hr(dict(form, agent_hr_quiet_hours="evenings"), modes, B)
    assert not ok and "quiet hours" in msg


def test_chat_settings_tool_routes_hr_keys(hr_db, tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    out = desk_tools.tickets_settings(tickets, None, r.SOLO, setting="agent_hr_enabled", value="on")
    assert "Saved" in out and store.settings()["agent_hr_enabled"] is True
    assert "agent_hr_enabled = on" in out and desk_db.get_settings(tickets).get("agent_hr_enabled") is False
    assert all(k in desk_tools.SETTING_HELP for k in das.HR_KEYS)
