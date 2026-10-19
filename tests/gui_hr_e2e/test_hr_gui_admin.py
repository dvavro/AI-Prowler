"""
HR Admin in a real browser (sandbox server; see conftest.py). Signs in through
the real sign-in screen, opens every menu tab, every Settings item and every
tab of an employee record, and fills in onboarding forms - failing on any
JavaScript error, an empty screen, or text like "undefined" / "coming in Week".
"""
import pytest

from hr_gui_helpers import USERS, bad_words, new_page, sign_in_admin, visible_text

ADMIN_TABS = ["employees", "messages", "tasks", "documents", "recruiting", "onboarding", "attendance", "clocklog",
              "timeoff", "payroll", "benefits", "performance", "training", "locations", "compliance", "incidents",
              "schedule", "reports", "offboarding", "terminations", "settings"]


@pytest.fixture(scope="module")
def admin(hr_browser, hr_sandbox):
    ctx, page, watch = new_page(hr_browser, "admin")
    sign_in_admin(page, hr_sandbox, "manager")
    yield page, watch
    ctx.close()


def _open_menu(page):
    # The side menu slides in from off-screen: open it the way a person does.
    if page.is_visible("#btn-hamburger"):
        page.click("#btn-hamburger")
        page.wait_for_timeout(450)


def _menu_click(page, tab, watch=None):
    if not page.is_visible("#btn-hamburger"):
        raise AssertionError("HR Admin isn't showing its main screen - auth screen visible: %s, wizard: %s, "
                             "refused requests: %s" % (page.is_visible("#auth-screen"), page.is_visible("#setup-wizard"),
                                                       (watch.refused if watch else "?")))
    _open_menu(page)
    page.locator(f'#sidebar-nav [data-tab="{tab}"]').click(timeout=8000)
    page.wait_for_timeout(1200)


def test_admin_signs_in_with_the_real_form(admin):
    page, watch = admin
    assert page.is_visible("#app") and not page.is_visible("#auth-screen")
    assert not watch.errors, watch.errors


def test_owner_can_sign_in_too_and_staff_cannot(hr_browser, hr_sandbox):
    ctx, page, _ = new_page(hr_browser, "owner")
    sign_in_admin(page, hr_sandbox, "owner")
    assert page.is_visible("#app")
    ctx.close()
    ctx, page, _ = new_page(hr_browser, "staff-at-admin")
    page.goto(f"{hr_sandbox.base}/hr_admin/")
    page.fill("#auth-name", USERS["anna"][0])
    page.fill("#auth-token", USERS["anna"][1])
    page.click("button.auth-btn")
    page.wait_for_timeout(2500)
    assert not page.is_visible("#app"), "a staff login must not open HR Admin"
    ctx.close()


@pytest.mark.parametrize("tab", ADMIN_TABS)
def test_every_menu_tab_opens_cleanly(admin, tab):
    page, watch = admin
    before = len(watch.errors)
    _menu_click(page, watch=watch, tab=tab)
    # Recruiting draws into its own body outside the (empty) tab container, by design
    pane = {"recruiting": "#rec-scroll-body"}.get(tab, f"#tab-{tab}")
    if not page.is_visible(pane):
        page.wait_for_timeout(1500)                         # slow first load
    shown = page.evaluate("() => [...document.querySelectorAll('.tab-pane')]"
                          ".filter(p => getComputedStyle(p).display !== 'none').map(p => p.id)")
    assert page.is_visible(pane), f"{tab}: its screen didn't show (showing: {shown}; JS errors: {watch.errors[before:]})"
    txt = visible_text(page, pane)
    assert len(txt.strip()) > 10, f"{tab}: screen is empty"
    assert not bad_words(txt), f"{tab}: shows {bad_words(txt)}"
    assert watch.errors[before:] == [], watch.errors[before:]


def test_company_setup_menu_item_opens_and_cancels(admin):
    page, watch = admin
    _open_menu(page)
    page.click("#sb-company-setup")
    page.wait_for_timeout(500)
    assert page.is_visible("#setup-wizard")
    assert page.input_value("#" + page.evaluate("WIZARD_STEPS[0].fields[0].id")) == "ZTEST Widgets LLC"
    page.click("#wizard-cancel-btn")
    page.wait_for_timeout(400)
    assert page.is_visible("#app") and not watch.errors, watch.errors


def test_every_settings_item_opens(admin):
    page, watch = admin
    _menu_click(page, watch=watch, tab="settings")
    items = page.locator("#tab-settings .settings-item[onclick]:not([onclick*='logout'])")   # Sign Out: own test
    n = items.count()
    assert n >= 8, n
    opened = []
    for i in range(n):
        it = items.nth(i)
        label = " ".join(it.inner_text().split())[:40]
        it.scroll_into_view_if_needed()
        it.click()
        page.wait_for_timeout(700)
        if page.is_visible("#setup-wizard"):
            opened.append(label); page.click("#wizard-cancel-btn"); page.wait_for_timeout(300)
        elif page.is_visible("#generic-modal"):
            opened.append(label)
            txt = visible_text(page, "#generic-modal")
            assert not bad_words(txt), (label, bad_words(txt))
            page.evaluate("closeModal()"); page.wait_for_timeout(300)
        _menu_click(page, watch=watch, tab="settings")
    assert len(opened) >= 8, opened
    assert not watch.errors, watch.errors


def test_employee_record_every_tab(admin, hr_sandbox):
    page, watch = admin
    _menu_click(page, watch=watch, tab="employees")
    page.evaluate(f"openEmpSheet('{hr_sandbox.employee_id('anna')}')")
    page.wait_for_timeout(1500)
    tabs = page.locator("#emp-sheet-tabs .emp-sheet-tab")
    names = []
    for i in range(tabs.count()):
        t = tabs.nth(i)
        names.append(t.inner_text().strip())
        t.click()
        page.wait_for_timeout(900)
    assert len(names) >= 6, names
    page.click("#emp-sheet-tabs >> text=Info"); page.wait_for_timeout(500)
    txt = visible_text(page, "#emp-sheet")
    assert "ZTEST" in txt and not bad_words(txt), bad_words(txt)
    assert not watch.errors, watch.errors


def test_onboarding_forms_save_on_the_server(admin, hr_sandbox):
    page, watch = admin
    anna = hr_sandbox.employee_id("anna")
    page.evaluate("closeEmpSheet && closeEmpSheet()")
    _menu_click(page, watch=watch, tab="onboarding")
    # record form: emergency contact -> employee record
    page.evaluate(f"obSelectedEmpId='{anna}'; openFormFill('emergency_contact','{anna}')")
    page.wait_for_timeout(500)
    page.fill("#ec1_name", "ZTEST Contact")
    page.fill("#ec1_rel", "Sibling")
    page.fill("#ec1_phone", "5550001111")
    page.click("#generic-modal .btn-primary")
    page.wait_for_timeout(1200)
    st, j = hr_sandbox.api("GET", f"/employees/{anna}")
    assert j["emergency_contact"]["name"] == "ZTEST Contact", j.get("emergency_contact")
    # signed form: W-4 with the paper copy on file
    page.evaluate(f"openFormFill('w4','{anna}')")
    page.wait_for_timeout(800)
    assert page.locator("#generic-modal input[type=file]").count() == 1
    assert "Social Security" not in visible_text(page, "#generic-modal")
    page.check("#sf-paper")
    page.click("#sf-save")
    page.wait_for_timeout(1200)
    st, j = hr_sandbox.api("GET", "/onboarding-forms")
    forms = {r["form"]: r["method"] for r in j["done"].get(anna, [])}
    assert forms.get("emergency_contact") == "record" and forms.get("w4") == "paper_copy", forms
    # Anna's folder shows the W-4 done (a step counts only when ALL its forms are done)
    page.evaluate(f"(() => {{ const f = document.getElementById('ob-folder-{anna}'); f.open = true;"
                  f" f.querySelectorAll('details').forEach(d => d.open = true); }})()")
    page.wait_for_timeout(300)
    folder = visible_text(page, f"#ob-folder-{anna}")
    w4_row = folder[folder.find("W-4"):][:120]
    assert "Done" in w4_row, w4_row
    assert not watch.errors, watch.errors


def test_sign_out_last(admin):
    page, watch = admin
    _menu_click(page, watch=watch, tab="settings")
    page.click("#tab-settings .settings-item[onclick*='logout']")
    page.wait_for_timeout(1000)
    assert page.is_visible("#auth-screen") and not page.is_visible("#app")
    assert page.evaluate("localStorage.getItem('hr_admin_token')") in (None, "")
