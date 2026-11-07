"""David 2026-11-06: the Setup Center's choices really switch things, and off and on again loses nothing."""
from __future__ import annotations

import json

import pytest

import setup_wizard as sw
import tool_config_store as tcs


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(tcs, "_state_dir", lambda: tmp_path)
    return tmp_path


def test_a_feature_is_on_until_someone_turns_it_off(cfg):
    for f in ("analyses", "email", "phone"):
        assert tcs.feature_on(f)
    assert tcs.feature_off_tools() == frozenset()


@pytest.mark.parametrize("f,tool", [("analyses", "create_analysis_task"), ("email", "send_email")])
def test_off_stops_the_features_tools_and_on_brings_them_back(cfg, f, tool):
    tcs.set_feature_on(f, False)
    assert tool in tcs.feature_off_tools()
    tcs.set_feature_on(f, True)
    assert tool not in tcs.feature_off_tools()


def test_route_tools_go_with_the_jobs_group_and_a_leftover_routes_switch_means_nothing(cfg):
    """David 2026-11-06: one switch. A routes-off saved by an earlier build must not take the route tools away."""
    import mcp_tool_catalog as cat
    assert "build_daily_route" in cat.tools_in_category("job_tracker")
    tcs.set_feature_on("routes", False)
    assert "build_daily_route" not in tcs.feature_off_tools()


def test_off_and_on_again_loses_nothing(cfg):
    """Bug 6: toggling a feature leaves a person's own tool choices and every other switch alone, however many times."""
    tcs.save_disabled_tools(["send_alert", "build_maps_url", "create_quote"], "personal")
    tcs.set_group_enabled("personal", "job_tracker", True)
    tcs.set_feature_on("phone", False)
    before = set(tcs.load_tool_config()["personal"]["disabled_tools"])
    for _ in range(3):
        for f in ("email", "analyses"):
            tcs.set_feature_on(f, False)
            assert set(tcs.load_tool_config()["personal"]["disabled_tools"]) == before
            tcs.set_feature_on(f, True)
    data = tcs.load_tool_config()
    assert set(data["personal"]["disabled_tools"]) == before
    assert not tcs.feature_on("phone") and tcs.saved_group_choice("personal", "job_tracker") is True
    assert not tcs.group_enabled("personal", "job_tracker"), "no Remote Access, no Jobs app"
    tcs.set_feature_on("phone", True)
    assert tcs.group_enabled("personal", "job_tracker"), "and back with it, as it was"


def test_only_the_tool_file_is_written(cfg, tmp_path):
    other = tmp_path / "email_config.json"
    other.write_text(json.dumps({"smtp_host": "mail.example.com"}), encoding="utf-8")
    for on in (False, True, False):
        tcs.set_feature_on("email", on)
    assert json.loads(other.read_text(encoding="utf-8")) == {"smtp_host": "mail.example.com"}


def test_jobs_off_and_on_again_keeps_individual_tool_choices(cfg):
    tcs.save_disabled_tools(["create_quote"], "personal")
    tcs.set_group_enabled("personal", "job_tracker", True)
    tcs.set_group_enabled("personal", "job_tracker", False)
    assert not tcs.group_enabled("personal", "job_tracker")
    tcs.set_group_enabled("personal", "job_tracker", True)
    assert tcs.group_enabled("personal", "job_tracker")
    assert "create_quote" in tcs.load_tool_config()["personal"]["disabled_tools"]


@pytest.mark.parametrize("phone,mode,want", [
    (False, "personal", False),                 # David: Remote Access off, no HTTP server, whatever else is ticked
    (True, "personal", True),
    (False, "server", True),                    # a server is nothing without it
])
def test_when_the_http_server_runs(cfg, phone, mode, want):
    tcs.set_group_enabled(mode, "job_tracker", True)
    tcs.set_group_enabled(mode, "service_desk", True)
    tcs.set_feature_on("phone", phone)
    assert tcs.http_server_wanted(mode) is want


def test_remote_access_off_turns_the_apps_off_everywhere_and_on_brings_them_back(cfg):
    """One answer for every screen, the tool list and the agents: they all read group_enabled."""
    for g in tcs.REMOTE_APP_GROUPS:
        tcs.set_group_enabled("personal", g, True)
    tcs.set_feature_on("phone", False)
    assert not any(tcs.group_enabled("personal", g) for g in tcs.REMOTE_APP_GROUPS)
    assert all(tcs.saved_group_choice("personal", g) is True for g in tcs.REMOTE_APP_GROUPS), "their own switches are kept"
    tcs.set_feature_on("phone", True)
    assert all(tcs.group_enabled("personal", g) for g in tcs.REMOTE_APP_GROUPS)


def test_turning_an_app_on_turns_remote_access_on(cfg):
    tcs.set_feature_on("phone", False)
    tcs.set_group_enabled("personal", "service_desk", True)
    assert tcs.feature_on("phone") and tcs.group_enabled("personal", "service_desk")


def test_a_server_ignores_the_phone_choice(cfg):
    tcs.set_feature_on("phone", False)
    tcs.set_group_enabled("server", "job_tracker", True)
    assert tcs.group_enabled("server", "job_tracker") and tcs.http_server_wanted("server")


@pytest.mark.parametrize("chosen,want", [
    (["business"], ["business"]),
    (["routes"], ["business"]),                 # an older saved choice
    (["files", "routes", "email"], ["files", "email", "business"]),
])
def test_crew_routes_are_part_of_the_jobs_app(chosen, want):
    assert sw.normalize_choices(chosen) == want


def test_the_setup_list_follows_the_switches(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "SYNC_SWITCHES", True)
    monkeypatch.setattr(sw, "desk_switched_on", lambda: False)
    monkeypatch.setattr(sw, "jobs_switched_on", lambda: False)
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["files", "email", "phone", "business"])
    tcs.set_feature_on("email", False)
    p.sync_switches()
    assert p.services == ["files", "phone"], "email is off, and jobs off takes routes with it"
    monkeypatch.setattr(sw, "jobs_switched_on", lambda: True)
    p.sync_switches()
    assert "business" in p.services


def test_setup_progress_is_kept_when_a_choice_goes_and_comes_back(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "SYNC_SWITCHES", False)
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["files", "email"])
    p.set_state("email", sw.DONE)
    p.choose(["files"])
    p.choose(["files", "email"])
    assert p.states["email"] == sw.DONE
    assert sw.Progress.load(tmp_path / "p.json").states["email"] == sw.DONE


def test_add_more_turns_the_feature_back_on(cfg, tmp_path):
    tcs.set_feature_on("email", False)
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["files"])
    p.add_service("email")
    assert tcs.feature_on("email") and "email" in p.services


# ── David 2026-11-06: the purple label said "jobs on" with the Jobs app off, and the agent really was still running ──
def _agent_on(monkeypatch, *, key=True):
    import desk_agent
    import desk_agent_store
    s = {"agent_jb_enabled": True, "agent_jb_shadow": True, "agent_jb_rt_enabled": True, "agent_jb_rt_shadow": True, "agent_provider": "claude_api"}
    monkeypatch.setattr(desk_agent_store, "settings", lambda: s)
    monkeypatch.setattr(desk_agent, "_has_key", lambda _s: key)


def test_the_label_says_not_enabled_with_the_jobs_app_off(cfg, monkeypatch):
    import desk_gui_agent as dga
    import desk_gui_links
    monkeypatch.setattr(desk_gui_links, "mode_of", lambda: "personal")
    _agent_on(monkeypatch)
    tcs.set_group_enabled("personal", "job_tracker", False)
    st = dga.agent_section_status("jobs")
    assert st["text"] == "(not enabled)" and not st["on"] and "jobs on" not in st["text"]
    tcs.set_group_enabled("personal", "job_tracker", True)
    assert "jobs on" in dga.agent_section_status("jobs")["text"]


def test_the_label_says_so_with_no_key(cfg, monkeypatch):
    import desk_gui_agent as dga
    import desk_gui_links
    monkeypatch.setattr(desk_gui_links, "mode_of", lambda: "personal")
    _agent_on(monkeypatch, key=False)
    tcs.set_group_enabled("personal", "job_tracker", True)
    assert "no API key" in dga.agent_section_status("jobs")["text"]


def test_the_jobs_agent_stops_with_the_jobs_app(cfg, monkeypatch, tmp_path):
    import desk_agent_store
    import desk_scheduler
    (tmp_path / "agent.db").write_text("")
    monkeypatch.setattr(desk_agent_store, "path", lambda: str(tmp_path / "agent.db"))
    looked = []
    monkeypatch.setattr(desk_agent_store, "sync_shared", lambda db: looked.append(db) or {})
    tcs.set_group_enabled("personal", "job_tracker", False)
    assert desk_scheduler.jobs_agent_tick(None, edition="solo") == {} and not looked, "it went on with the app off"
    tcs.set_group_enabled("personal", "job_tracker", True)
    desk_scheduler.jobs_agent_tick(None, edition="solo")
    assert looked, "it should run again with the app on"


def test_the_hr_agent_stops_with_the_hr_apps(cfg, monkeypatch, tmp_path):
    import desk_agent_hr_store
    import desk_scheduler
    (tmp_path / "hr_agent.db").write_text("")
    monkeypatch.setattr(desk_agent_hr_store, "path", lambda: str(tmp_path / "hr_agent.db"))
    looked = []
    monkeypatch.setattr(desk_agent_hr_store, "sync_shared", lambda db, adb: looked.append(db) or {})
    tcs.set_hr_apps_enabled(False)
    assert desk_scheduler.hr_agent_tick(None, edition="business") == {} and not looked, "it went on with the apps off"
    tcs.set_hr_apps_enabled(True)
    desk_scheduler.hr_agent_tick(None, edition="business")
    assert looked, "it should run again with the apps on"
