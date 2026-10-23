"""AICP-01..AICP-05 — "📋 Copy AI Route for Any AI" on the Route tab (2026-10-22).

For users not using the Claude CLI: the button gets a ready-made prompt from
AI-Prowler (get_ai_route_prompt), copies it, and shows it in a sheet with Copy,
Refresh route and Close. The user pastes it into Claude, Muse, Grok or any chat
that has this AI-Prowler connected. The prompt carries a one-time route code so
the chat uses THIS AI-Prowler (the code checks themselves — confirm_route_code
and apply_route_order refusing a foreign code — are unit-tested in
tests/mcp_tests/test_copy_ai_route_prompt.py; the Jobs-app API doesn't expose
apply_route_order).

  AICP-01  PC: the button sits between Route and 📧 Email (it replaced the 🧠 AI
           Route / Claude CLI button, 2026-10-22); phone shows "📋 Any AI"
  AICP-02  tap -> sheet with route code, made-by, the full prompt, "✅ Copied"
  AICP-03  the clipboard really holds the prompt; Copy copies again
  AICP-04  Refresh route closes the sheet
  AICP-05  a pre-check problem the user chooses to fix -> no prompt is made

Sandbox data only (ZTEST_). Run visibly, like every Jobs GUI test:
    run_tests.bat jobs-sandbox --human -k AICP
"""
import re

import pytest
from playwright.sync_api import expect

from safety import SANDBOX_DATE


@pytest.fixture
def one_job(clean_slate, data):
    data.job("AICP route job", "city_hall")
    return data


def _open_sheet(route, page):
    route.pick_date(SANDBOX_DATE)
    page.locator("#routeCopyAiBtn").click()
    sheet = page.locator("#aiRouteOverlay")
    expect(sheet).to_be_visible(timeout=30_000)
    expect(sheet.locator("[data-testid=ai-route-prompt-code]")).to_have_text(
        re.compile(r"^RT-[A-Z0-9]{6}$"), timeout=30_000)
    return sheet


def test_AICP_01_button_next_to_route(route, page, app):
    page.set_viewport_size({"width": 1366, "height": 768})
    rt, cp, em = (page.locator(s) for s in ("#routeTodayBtnRoute", "#routeCopyAiBtn", "#routeEmailRouteBtn"))
    expect(cp).to_be_visible()
    expect(cp).to_contain_text("Copy AI Route for Any AI")
    expect(page.locator("#routeAiSuggestBtn")).to_have_count(0)     # 🧠 CLI button removed 2026-10-22
    xs = [loc.bounding_box()["x"] for loc in (rt, cp, em)]
    app.step(f"ROUTE buttons left edges: Route {xs[0]:.0f}, Copy {xs[1]:.0f}, Email {xs[2]:.0f}")
    assert xs[0] < xs[1] < xs[2], xs
    page.set_viewport_size({"width": 390, "height": 844})
    page.wait_for_timeout(300)
    expect(cp.locator(".lbl-short")).to_be_visible()
    expect(cp.locator(".lbl-short")).to_have_text("📋 Any AI")
    page.set_viewport_size({"width": 1366, "height": 768})


def test_AICP_02_sheet_shows_the_prompt(route, page, app, one_job):
    sheet = _open_sheet(route, page)
    code = sheet.locator("[data-testid=ai-route-prompt-code]").inner_text().strip()
    meta = sheet.locator("[data-testid=ai-route-prompt-meta]").inner_text()
    text = page.locator("#aiRoutePromptText").input_value()
    app.step(f"PROMPT {code} made by: {meta}")
    assert "AI-Prowler" in meta and "24 hours" in meta
    assert text.startswith("AI-PROWLER ROUTE REQUEST")
    assert f'confirm_route_code(code="{code}")' in text
    assert f'route_code="{code}"' in text and SANDBOX_DATE in text
    assert "do NOT read the Settings sheet" in text
    expect(sheet.locator("[data-testid=ai-route-prompt-status]")).to_have_text(
        re.compile(r"Copied|Tap 📋 Copy"), timeout=10_000)
    sheet.locator("#acpClose").click()
    expect(sheet).to_have_count(0)


def test_AICP_03_clipboard_holds_the_prompt(route, page, app, one_job, app_url):
    try:
        page.context.grant_permissions(["clipboard-read", "clipboard-write"],
                                       origin=re.match(r"https?://[^/]+", app_url).group(0))
    except Exception:
        pass
    sheet = _open_sheet(route, page)
    expect(sheet.locator("[data-testid=ai-route-prompt-status]")).to_contain_text("Copied", timeout=10_000)
    text = page.locator("#aiRoutePromptText").input_value()
    page.evaluate("() => navigator.clipboard.writeText('something else')")
    sheet.locator("[data-testid=ai-route-prompt-copy]").click()
    expect(sheet.locator("[data-testid=ai-route-prompt-status]")).to_contain_text("Copied", timeout=10_000)
    clip = page.evaluate("() => navigator.clipboard.readText()")
    app.step(f"CLIPBOARD {len(clip)} chars, prompt {len(text)} chars")
    # The Windows clipboard stores line breaks as \r\n — same text when pasted.
    assert clip.replace("\r\n", "\n") == text.replace("\r\n", "\n")
    sheet.locator("#acpClose").click()


def test_AICP_04_refresh_closes_the_sheet(route, page, app, one_job):
    sheet = _open_sheet(route, page)
    sheet.locator("[data-testid=ai-route-prompt-refresh]").click()
    expect(sheet).to_have_count(0, timeout=10_000)
    expect(page.locator("#toast")).to_contain_text("Route refreshed", timeout=15_000)
    expect(page.locator("#routeCopyAiBtn")).to_be_enabled()
    expect(page.locator("#routeTodayBtnRoute")).to_be_enabled()


def test_AICP_05_fix_first_makes_no_prompt(route, page, app, clean_slate, data):
    data.job("AICP dup A", "city_hall")
    data.job("AICP dup B", "city_hall")                 # same address -> a pre-check error
    route.pick_date(SANDBOX_DATE)
    asked = []
    page.once("dialog", lambda d: (asked.append(d.message), d.dismiss()))   # Cancel = fix first
    page.locator("#routeCopyAiBtn").click()
    expect(page.locator("#toast")).to_contain_text("Fix the jobs", timeout=30_000)
    assert asked and "Prescreen found" in asked[0]
    expect(page.locator("#aiRouteOverlay")).to_have_count(0)
