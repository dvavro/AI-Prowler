"""Server mode — SRV-SCR-08 (spec §6.11.5): the button sweep, once per role.

For each user (U1 David · owner, U2 Vicki · manager, U3 Samual · field_crew):
visit every screen that user's bottom nav shows, and click every button the
personal-mode sweep already classifies as SAFE (test_buttons.KNOWN and
test_buttons_other.KNOWN_OTHER). WRITE and GUARDED buttons are never clicked
here — they're covered by their own tests — and neither is Sign Out.

A click fails the test when it causes any of:
  * a JavaScript error on the page (pageerror)
  * an HTTP 5xx from the server
  * "Unknown tool" — the screen calls a tool the server doesn't allow for
    the Jobs app at all (a broken button in server mode)
  * a SILENT denial — the server refuses the call ("❌ …") and nothing
    appears on screen (no toast, the refusal text isn't shown). Background
    reads of sheets field crew can't see (Settings etc.) are exempt: the app
    falls back to defaults for those on purpose.

Buttons found that aren't in the personal-mode lists are NOT clicked (they
could write or send); they're listed in the log and in
srv_buttons_inventory.json so they can be classified.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_buttons
"""
import json
import os
from pathlib import Path

import pytest
from playwright.sync_api import expect

from test_buttons import INVENTORY_JS, KNOWN, _key, screen_selector
from test_buttons_other import KNOWN_OTHER

NEVER_CLICK = {"profile-signout",        # would end the session mid-sweep
               "getElementById"}         # Photos 📷/📎 open the OS file picker
EXEMPT_READS = {"read_job_spreadsheet", "get_sheet_columns"}   # quiet fallbacks by design

SAFE = {screen: {k for k, v in m.items() if v == "SAFE" and k not in NEVER_CLICK}
        for screen, m in {**KNOWN, **KNOWN_OTHER}.items()}
# Database screen ("sheet"): the personal suite covers it in test_database.py
# (BTN-DB), not in a KNOWN list, so its read-only buttons are named here — the
# sheet tabs (which differ by role: field crew has no Settings / Pricing /
# Quotes / Invoices), Refresh and Hide Completed. "+ Add" and "Edit" open write
# forms and stay unclicked. (Found by the first SRV-SCR-08 run, 2026-09-27.)
SAFE["sheet"] = {"refreshSheetBtn", "hideCompletedBtn", "📋 Jobs", "👤 Customers", "⏱ TimeLog",
                 "🗺 Route", "📖 Commands", "⚙ Settings", "💰 Pricing", "💲 Quotes", "🧾 Invoices"}


def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


def _button_locator(page, screen, b):
    root = page.locator(screen_selector(screen))
    if b["id"]:
        return root.locator(f"#{b['id']}").first
    if b["testid"]:
        return root.locator(f"[data-testid=\"{b['testid']}\"]").first
    if b["calls"]:
        return root.locator(f"[onclick*=\"{b['calls']}(\"]").first
    return root.get_by_text(b["text"], exact=True).first


def _is_denial(result) -> bool:
    return isinstance(result, str) and result.lstrip().startswith("❌")


@pytest.fixture
def sweep_jobs(clean_slate, data, srv):
    """Two ZTEST jobs on the sandbox date per user, so cards / chips / route
    rows exist on every screen for every role."""
    ids = []
    for u in srv["users"].values():
        ids.append(data.job(f"BTN {u.key}", **{"Crew / Technician": u.name,
                                              "Est. Duration": 30, "Est. Duration Unit": "min"}))
    return ids


@pytest.mark.parametrize("key", ["U1", "U2", "U3"])
def test_SRV_SCR_08_button_sweep_per_role(windows, sweep_jobs, key):
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    page = w.page

    page_errors, api = [], []
    page.on("pageerror", lambda e: page_errors.append(str(e)))

    def on_response(r):
        if "/pwa-api" not in r.url:
            return
        try:
            body = json.loads(r.request.post_data or "{}")
            tool = body.get("tool", "")
        except Exception:
            tool = ""
        try:
            j = r.json()
        except Exception:
            j = {}
        api.append({"tool": tool, "status": r.status, "ok": j.get("ok"),
                    "result": j.get("result", j.get("error", ""))})
    page.on("response", on_response)

    problems, not_clicked, clicked, inventory = [], [], [], {}
    screens = w.app.visible_screens()
    w.app.log(f"{key} ({w.user.name}) sees screens: {screens}")

    for screen in screens:
        w.app.goto(screen)
        page.wait_for_timeout(1500)
        found = page.evaluate(INVENTORY_JS, screen_selector(screen))
        inventory[screen] = found
        safe_here = SAFE.get(screen, set())
        # one click per distinct key (e.g. one job card stands for all of them)
        todo = {}
        for b in found:
            k = _key(b)
            if k in safe_here and not b["disabled"]:
                todo.setdefault(k, b)
            elif k not in safe_here:
                not_clicked.append(f"{screen}:{k}")

        for k, b in todo.items():
            before_err, before_api = len(page_errors), len(api)
            try:
                _button_locator(page, screen, b).click(timeout=8_000)
            except Exception as exc:  # hidden behind something / gone after a reload
                w.app.log(f"{key} {screen}:{k} not clickable ({str(exc).splitlines()[0][:120]})")
                continue
            clicked.append(f"{screen}:{k}")
            page.wait_for_timeout(1800)
            toast = page.locator("#toast")
            toast_text = toast.inner_text() if "show" in (toast.get_attribute("class") or "") else ""
            body_text = page.locator("body").inner_text()

            for e in page_errors[before_err:]:
                problems.append(f"{screen}:{k} → JavaScript error: {e[:200]}")
            for c in api[before_api:]:
                res = str(c["result"])
                if c["status"] >= 500:
                    problems.append(f"{screen}:{k} → {c['tool']} HTTP {c['status']}")
                elif "Unknown tool" in res:
                    problems.append(f"{screen}:{k} → {c['tool']} is not allowed in server mode (\"Unknown tool\")")
                elif _is_denial(res) and c["tool"] not in EXEMPT_READS:
                    shown = bool(toast_text) or res.lstrip("❌ ").strip()[:25] in body_text
                    w.app.log(f"{key} {screen}:{k} → {c['tool']} refused ({res[:100]!r}); shown on screen: {shown}")
                    if not shown:
                        problems.append(f"{screen}:{k} → {c['tool']} refused SILENTLY: {res[:120]!r}")

            # back to a clean screen: close whatever the button opened
            page.keyboard.press("Escape")
            page.reload(wait_until="domcontentloaded")
            _signed_in(w)
            w.app.goto(screen)
            page.wait_for_timeout(800)

    run_dir = Path(os.environ.get("E2E_RUN_DIR") or ".")
    (run_dir / f"srv_buttons_inventory_{key}.json").write_text(
        json.dumps({"user": w.user.name, "screens": screens, "clicked": clicked,
                    "not_clicked_unclassified": sorted(set(not_clicked)), "inventory": inventory},
                   indent=1, ensure_ascii=False), encoding="utf-8")
    w.app.log(f"{key} clicked {len(clicked)} buttons: {clicked}")
    if not_clicked:
        w.app.log(f"{key} NOT clicked (not in the personal-mode SAFE lists): {sorted(set(not_clicked))}")
    assert clicked, f"{key}: no buttons were clicked — the sweep found nothing to test"
    assert not problems, f"{key} ({w.user.name}) button problems:\n  " + "\n  ".join(problems)
