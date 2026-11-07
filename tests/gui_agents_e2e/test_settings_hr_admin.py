"""AG-HR-16 / AG-HR-17 — HR Admin's 🤖 Agent tab, from the app's side.

The HR apps (HR Admin, HR Portal) run on an AI-Prowler SERVER only ("hr_server_only" on a personal install), and
on a server the agents are set up at the server PC — so HR Admin's agent settings are always greyed out
(test_settings_server_readonly.py). The field-by-field HR checks (AG-HR-01…15) therefore run against the desktop
👥 HR Agent & settings section — test_settings_desktop.py.

Here: the app can't change them, and only HR Admin sees the agent.
"""
from __future__ import annotations

import pytest

SETUP = {"company_name": "ZAG Agents Co", "work_states": ["FL"], "setup_complete": True,
         "hr_admin_email": "owner@time-machine.test", "owner_email": "owner@time-machine.test"}


@pytest.fixture
def hr_box(business):
    st, j = business.hr("POST", "/setup/complete", SETUP)
    assert st == 200, j
    return business


def test_hr_apps_are_server_only(solo):
    st, j = solo.hr("GET", "/agent/status")
    assert st == 404 and j.get("error") == "hr_server_only", (st, j)


def test_hr_16_server_refuses_any_settings_change(hr_box):
    before = hr_box.settings()["hr"]
    for body in ({"agent_hr_enabled": not before["agent_hr_enabled"]}, {"agent_hr_bogus": 1}):
        st, j = hr_box.hr("POST", "/agent/settings", {"settings": body})
        assert st == 403, (body, st, j)
    after = hr_box.settings()["hr"]
    assert after == before and "agent_hr_bogus" not in after


def test_hr_admin_reads_status_and_settings(hr_box):
    st, j = hr_box.hr("GET", "/agent/settings")
    assert st == 200 and j["can_change_settings"] is False, (st, j)
    st, j = hr_box.hr("GET", "/agent/status")
    assert st == 200 and j["can_change_settings"] is False, (st, j)


@pytest.mark.parametrize("who,allowed", [("manager", True), ("staff", False)])
def test_hr_17_only_hr_admin_sees_the_agent(hr_box, who, allowed):
    """HR Admin = a team role with can_manage_hr (owner, manager); anyone else gets 403 admin_only."""
    for path in ("/agent/status", "/agent/settings", "/agent/pending"):
        st, j = hr_box.hr("GET", path, key=who)
        if allowed:
            assert st == 200, (who, path, st, j)
        else:
            assert st == 403 and j.get("error") == "admin_only", (who, path, st, j)
