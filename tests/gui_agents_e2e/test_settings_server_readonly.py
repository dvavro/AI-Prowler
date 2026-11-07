"""AG-SD-13 / AG-JB-11 / AG-HR-17 (David 2026-11-03): on a SERVER the agents are set up at the server PC only,
so nobody can change them from the apps. "Grayed out is OK":
  * Service Desk app — the ⚙︎ Settings tab isn't shown at all on a server;
  * Jobs app and HR Admin — the agent settings show greyed out (every box disabled, no Save button), with the
    note saying they're changed at the server PC.
A Solo (personal) install keeps working controls — the owner is the one using the app.
"""
from __future__ import annotations


def _all_disabled(page, scope: str):
    boxes = page.locator(f"{scope} input, {scope} select, {scope} textarea")
    n = boxes.count()
    assert n > 0, f"no settings shown in {scope}"
    live = [i for i in range(n) if boxes.nth(i).is_enabled()]
    assert not live, f"{len(live)} of {n} box(es) in {scope} can still be changed"
    assert page.locator(f"{scope} button").count() == 0, f"a Save button is shown in {scope}"


def test_server_service_desk_has_no_settings_tab(business, person):
    owner = person(business, "owner")
    owner.desk_sign_in()
    assert not owner.page.locator("#tabSettings").is_visible()
    owner.pause(1500)


def test_server_jobs_app_settings_are_greyed_out(business, person):
    owner = person(business, "owner")
    owner.jobs_sign_in()
    owner.page.locator("#navAgent").click()
    owner.page.locator("#agSettingsBox summary").click()
    owner.page.locator("#agSettings select").first.wait_for()
    assert "server PC" in owner.page.locator("#agSettings").inner_text()
    _all_disabled(owner.page, "#agSettings")
    owner.pause(2500)


def test_server_hr_admin_settings_are_greyed_out(business, person):
    st, j = business.hr("POST", "/setup/complete", {"company_name": "ZAG Agents Co", "work_states": ["FL"],
                                                    "setup_complete": True, "hr_admin_email": "owner@time-machine.test",
                                                    "owner_email": "owner@time-machine.test"})
    assert st == 200, j
    admin = person(business, "hr-admin")
    admin.hr_admin_sign_in()
    btn = admin.page.locator("[data-tab='agent']").first
    btn.evaluate("b => { b.scrollIntoView({block: 'center'}); b.click(); }")
    admin.page.locator("#hrag-settings select").first.wait_for()
    assert "server PC" in admin.page.locator("#hrag-settings").inner_text()
    _all_disabled(admin.page, "#hrag-settings")
    admin.pause(2500)


def test_solo_owner_keeps_working_controls(solo, person):
    owner = person(solo, "owner")
    owner.desk_sign_in()
    owner.page.locator("#tabSettings").click()
    owner.page.locator("#agentCard").wait_for()
    assert owner.page.locator("#agentCard [data-agb='agent_enabled']").is_enabled()
    assert owner.page.locator("#agentCard #agSave").count() == 1
    owner.pause(1500)
