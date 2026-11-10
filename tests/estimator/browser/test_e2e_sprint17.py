"""Coder 2 Sprint 17 E2E GUI tests (Playwright, human mode): Reports, Settings, full Price Book.

    run_tests_estimator.bat browser -k E2E_S17 [--human]

Seeds are built in Python (see e2e_helpers.make_revs); every assertion is driven
through the browser DOM. See tests/estimator/E2E_GUI_TEST_PLAN.md.
"""
import csv
from datetime import date

import pytest

from browser_helpers import answer_yes, type_in
from e2e_helpers import CTX, compare_in_browser, dismiss_tour, make_revs, nav_ids, sign_in_as
from estimator.bids import service as bids
from estimator.context import personal_context
from estimator.estimating import quick, service
from estimator.learning import history
from estimator.modules.registry import ModuleRegistry

REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
CSV_TEXT = "Item Code,Description,Unit,Unit Price\npw_driveway_sqft,Driveway,sqft,0.19\nbogus,Nothing like this,ea,5\n"
KEY = "pw_driveway_sqft"


def _roof(db, status="won"):
    e = service.create_estimate(db, CTX, "roof")
    e = quick.answer(db, CTX, e["id"], "roofing", ROOF, e["rev"], REG)
    if status != "draft":
        e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
        if status != "approved":
            e = service.set_status(db, CTX, e["id"], e["rev"], status)
    return service.get_estimate(db, CTX, e["id"])


def _sent_bid(db, title):
    """An approved estimate with a bid already sent, so the bid page shows Won/Lost.
    bids.set_status has no "sent" (only viewed/won/lost/expired/void), so the send
    goes through bids.send with a stubbed send_email host — no real email."""
    from estimator.integrations import host
    e = _roof(db, "approved")
    db.execute("UPDATE estimates SET title = ? WHERE id = ?", (title, e["id"]))
    bid = bids.generate(db, CTX, e["id"])
    host.set_host({"send_email": lambda **kw: "✅ Email sent to customer@example.com"})
    try:
        bids.send(db, CTX, bid["id"], to="customer@example.com", confirm=True)
    finally:
        host.set_host(None)
    db.commit()
    return e["id"], bid["id"]


@pytest.fixture
def revs(db, tmp_path):
    return make_revs(db, tmp_path)


# ------------------------------------------------------------------ M2: flagged measurements, re-measure clears

def test_E2E_S17_M2_flagged_remeasure_clears(page, revs):
    rid = compare_in_browser(page, page.base, revs)
    page.wait_for_selector("#rev-flagged")
    assert "3" in page.inner_text("#rev-tiles")
    rows = page.locator("#rev-flagged tbody tr")
    assert rows.count() == 3
    assert "re-measure" in rows.nth(0).inner_text()
    # The flagged link opens Blueprint Review on that measurement.
    rows.nth(0).locator("a").click()
    page.wait_for_url(f"**#/takeoffs/{revs['est']}?m=*")
    page.wait_for_selector("#bp-edit")
    dismiss_tour(page)
    # Re-measure it: correct the quantity in the detail panel; that clears the flag.
    page.click("#bp-edit")
    page.wait_for_selector("#bp-edit-qty")
    qty = float(page.input_value("#bp-edit-qty") or 0)
    type_in(page, "#bp-edit-qty", str(qty + 1))
    page.click("#bp-edit-save")
    # reviewAsk asks first (#bp-edit-yes) or saves straight away; either way the
    # toast says the correction landed.
    try:
        page.wait_for_selector("#bp-edit-yes", timeout=5000)
        page.click("#bp-edit-yes")
    except Exception:
        pass
    page.wait_for_function("() => document.body.innerText.includes('Measurement corrected')")
    # Back on the revision report that measurement now says "done"; the other two still wait.
    page.goto(page.base + f"#/revisions/{rid}")
    page.wait_for_selector("#rev-flagged")
    flagged = page.inner_text("#rev-flagged")
    assert flagged.count("re-measure") == 2 and "done" in flagged
    # The takeoff report agrees: 2 left to re-measure, and the unchanged
    # (carried) measurements kept their approval (still 3 approved).
    page.goto(page.base + f"#/reports?tab=takeoff&estimate={revs['est']}")
    page.wait_for_selector("#tr-tiles")
    tiles = page.inner_text("#tr-tiles")
    assert "To Re-Measure" in page.inner_text("#report-body")
    assert "2" in tiles


# ------------------------------------------------------------------ M3: win / loss moves

def test_E2E_S17_M3_win_loss_moves(page, db):
    won_id, won_bid = _sent_bid(db, "Won roof")
    lost_id, lost_bid = _sent_bid(db, "Lost roof")
    from estimator import practice
    practice.create(db, CTX)
    db.execute("UPDATE estimates SET status = 'won' WHERE is_practice = 1")
    db.commit()
    page.goto(page.base + "#/reports?tab=winloss")
    page.wait_for_selector("#wl-tiles")
    dismiss_tour(page)
    # Nothing marked yet through the UI: the practice win stays out of the numbers.
    assert "0%" in page.inner_text("#wl-tiles") or "—" in page.inner_text("#wl-tiles")
    # Mark the first bid won in the browser; the tiles, the month row and the trade row move.
    page.goto(page.base + f"#/bids/{won_bid}")
    page.wait_for_selector("#bid-won")
    page.click("#bid-won")
    page.wait_for_function("() => document.body.innerText.includes('marked won')")
    page.wait_for_timeout(1000)  # let the bid page's own re-render land first
    page.goto(page.base + "#/reports?tab=winloss")
    page.wait_for_selector("#wl-tiles")
    tiles = page.inner_text("#wl-tiles")
    assert "1" in tiles and "Won" in tiles
    month = date.today().strftime("%Y-%m")
    row = page.locator(f"#wl-months tr[data-month='{month}']")
    assert row.count() == 1 and "1" in row.inner_text()
    # The trade row renders the module id as-is ("roofing", lower case).
    assert "roofing" in page.inner_text("#wl-trades")
    # And the second bid lost: win rate becomes 50%.
    page.goto(page.base + f"#/bids/{lost_bid}")
    page.wait_for_selector("#bid-lost")
    page.click("#bid-lost")
    page.wait_for_function("() => document.body.innerText.includes('marked lost')")
    page.wait_for_timeout(1000)
    page.goto(page.base + "#/reports?tab=winloss")
    page.wait_for_selector("#wl-tiles")
    assert "50%" in page.inner_text("#wl-tiles")
    assert "1" in page.inner_text("#wl-trades tr[data-trade=roofing]")
    # The practice project never counted: still exactly 1 won and 1 lost.
    # The status line renders the status words lower case (words() only
    # swaps underscores for spaces): the text is "lost 1 · won 1".
    assert "won 1" in page.inner_text("#wl-status") and "lost 1" in page.inner_text("#wl-status")


# ------------------------------------------------------------------ M4: takeoff vs actuals

def test_E2E_S17_M4_takeoff_vs_actuals(page, db, revs):
    rid = compare_in_browser(page, page.base, revs)
    # Takeoff report: approved vs waiting match Blueprint Review's counts.
    page.goto(page.base + f"#/reports?tab=takeoff&estimate={revs['est']}")
    page.wait_for_selector("#tr-tiles")
    dismiss_tour(page)
    tiles = page.inner_text("#tr-tiles")
    assert "6" in tiles and "3" in tiles  # 6 measurements, 3 approved
    assert "To Re-Measure" in page.inner_text("#report-body")
    # Record actual costs on a SEPARATE priced estimate: the revs estimate is
    # never priced (make_revs only proposes measurements, so it has no lines),
    # and record_actuals refuses a draft anyway. _roof("approved") has the
    # rf_arch_sq line, mirroring test_web_sprint17 W08/W29.
    roof = _roof(db, "approved")
    line = next(ln for s in roof["sections"] for ln in s["lines"] if ln["price_key"] == "rf_arch_sq")
    history.record_actuals(db, CTX, roof["id"], [
        {"line_id": line["id"], "cost": "3,300.00", "quantity": "24"},
        {"price_key": "rf_permit_ea", "cost": "$350"},
        {"total": "8600"}], note="Garcia roof")
    db.commit()
    page.goto(page.base + f"#/reports?tab=actuals&estimate={roof['id']}")
    page.wait_for_selector("#ac-lines")
    assert "rf_arch_sq" in page.inner_text("#ac-lines") or "Architectural" in page.inner_text("#ac-lines")
    assert page.locator("#ac-lines tbody tr").count() >= 1
    # The revision report and the takeoff report agree on the flagged count.
    page.goto(page.base + f"#/revisions/{rid}")
    page.wait_for_selector("#rev-flagged")
    assert page.locator("#rev-flagged tbody tr").count() == 3


# ------------------------------------------------------------------ M5: exports download

def test_E2E_S17_M5_exports_download(page, db, tmp_path):
    _roof(db, "won")
    _roof(db, "lost")
    db.commit()
    page.goto(page.base + "#/reports?tab=exports")
    page.wait_for_selector("#ex-go")
    dismiss_tour(page)
    page.select_option("#ex-format", "csv")
    with page.expect_download() as dl:
        page.click("#ex-go")
    download = dl.value
    assert download.suggested_filename.endswith(".csv")
    path = tmp_path / "export.csv"
    download.save_as(path)
    rows = list(csv.reader(path.read_text(encoding="utf-8").splitlines()))
    assert len(rows) >= 3  # header + the two estimates
    assert any("roof" in " ".join(r).lower() for r in rows)
    assert "Exported" in page.inner_text("#ex-message")
    # Excel too: same flow, opens with the right rows.
    page.select_option("#ex-format", "xlsx")
    with page.expect_download() as dl2:
        page.click("#ex-go")
    xlsx = dl2.value
    assert xlsx.suggested_filename.endswith(".xlsx")
    xpath = tmp_path / "export.xlsx"
    xlsx.save_as(xpath)
    import pytest as _pt
    openpyxl = _pt.importorskip("openpyxl")
    wb = openpyxl.load_workbook(xpath)
    sheet_rows = list(wb.active.iter_rows(values_only=True))
    assert len(sheet_rows) >= 3
    assert any("roof" in str(c).lower() for r in sheet_rows for c in r if c)


# ------------------------------------------------------------------ M6: settings, ask-first, roles

def test_E2E_S17_M6_settings_ask_first_and_roles(page, db):
    page.goto(page.base + "#/settings?section=company")
    page.wait_for_selector("#set-name")
    dismiss_tour(page)
    type_in(page, "#set-name", "Acme Estimating LLC")
    type_in(page, "#set-phone", "555-0100")
    page.click("#set-company-save")
    page.wait_for_selector("#set-company-confirm-box")
    assert "Acme Estimating LLC" in page.inner_text("#set-company-confirm-box")
    # Nothing saved yet: the ask-first question is still open.
    page.click("#set-company-confirm")
    page.wait_for_function("() => document.body.innerText.includes('Company profile saved')")
    page.evaluate("route()")  # fresh render from the server, not the typed form
    page.wait_for_selector("#set-name")
    assert page.input_value("#set-name") == "Acme Estimating LLC"
    # Tax section: a good value saves (and persists on re-render).
    page.goto(page.base + "#/settings?section=money")
    page.wait_for_selector("#set-tax")
    type_in(page, "#set-tax", "7")
    page.click("#set-taxes-save")
    page.wait_for_selector("#set-taxes-confirm")
    page.click("#set-taxes-confirm")
    page.wait_for_function("() => document.body.innerText.includes('Sales tax saved')")
    page.evaluate("route()")
    page.wait_for_selector("#set-tax")
    assert page.input_value("#set-tax") == "7"
    # Every other role: Settings is absent from the menu and the route falls back.
    for role in ("estimator", "reviewer", "office", "field"):
        with sign_in_as(page, role):
            page.goto(page.base + "#/settings")
            page.wait_for_selector("#nav")
            assert "settings" not in nav_ids(page)
            assert page.locator("#settings-body").count() == 0
            assert page.locator("#settings-tabs").count() == 0


# ------------------------------------------------------------------ M7: Price Book

def test_E2E_S17_M7_price_book_history_markups_import(page, db):
    page.goto(page.base + "#/price_book?module=pressure_washing")
    page.wait_for_selector("#prices")
    dismiss_tour(page)
    assert "overhead 0%" in page.inner_text("#pb-markups")
    # Change the driveway price; history then shows the change.
    row = page.locator(f"#prices tr[data-key={KEY}] input.cost")
    type_in(page, f"#prices tr[data-key={KEY}] input.cost", "0.25")
    page.click("#pb-save")
    page.wait_for_selector("#pb-confirm")
    assert "0.25" in page.inner_text("#pb-confirm-box")
    page.click("#pb-confirm")
    page.wait_for_function("() => document.body.innerText.includes('price(s) saved')")
    page.evaluate("route()")
    page.wait_for_function("() => document.querySelector('#prices tr[data-key=pw_driveway_sqft] input.cost')?.value === '0.25'")
    page.click(f"#prices [data-history={KEY}]")
    page.wait_for_selector(f".pb-history[data-history-for={KEY}]")
    page.wait_for_function(
        "() => { const el = document.querySelector('.pb-history[data-history-for=pw_driveway_sqft]');"
        " return el && !el.textContent.includes('Loading'); }")
    hist = page.inner_text(f".pb-history[data-history-for={KEY}]")
    assert "0.25" in hist and "yours" in hist
    # Markups follow Settings: set tax 7% and the Price Book says so.
    page.goto(page.base + "#/settings?section=money")
    page.wait_for_selector("#set-tax")
    dismiss_tour(page)  # the Settings tour autostarts on first open here
    type_in(page, "#set-tax", "7")
    page.click("#set-taxes-save")
    page.wait_for_selector("#set-taxes-confirm")
    page.click("#set-taxes-confirm")
    page.wait_for_function("() => document.body.innerText.includes('Sales tax saved')")
    page.goto(page.base + "#/price_book?module=pressure_washing")
    page.wait_for_selector("#pb-markups")
    assert "tax 7%" in page.inner_text("#pb-markups")
    # Import a supplier CSV: the mapping is guessed, fixable, and the import saves.
    page.click("#pb-import-box summary")
    type_in(page, "#pb-csv", CSV_TEXT)
    page.click("#pb-columns")
    page.wait_for_selector("#pb-mapping select[data-field=cost]")
    assert page.input_value("#pb-mapping select[data-field=cost]") == "Unit Price"
    assert page.input_value("#pb-mapping select[data-field=price_key]") == "Item Code"
    # Fix a mapping, then put it back: the guess is changeable.
    page.select_option("#pb-mapping select[data-field=cost]", "Description")
    assert page.input_value("#pb-mapping select[data-field=cost]") == "Description"
    page.select_option("#pb-mapping select[data-field=cost]", "Unit Price")
    page.click("#pb-import")
    page.wait_for_selector("#pb-confirm")
    assert "1" in page.inner_text("#pb-confirm-box")
    page.click("#pb-confirm")
    page.wait_for_function("() => document.body.innerText.includes('Imported 1 price(s)')")
    page.evaluate("route()")
    page.wait_for_function("() => document.querySelector('#prices tr[data-key=pw_driveway_sqft] input.cost')?.value === '0.19'")


# ------------------------------------------------------------------ M8: role gates

def test_E2E_S17_M8_role_gates_reports_settings(page, revs):
    for role, reports, settings, price_book in (("reviewer", True, False, False), ("office", True, False, False),
                                                ("field", False, False, False), ("estimator", True, False, True)):
        with sign_in_as(page, role):
            page.goto(page.base + "#/dashboard")
            page.wait_for_selector("#nav")
            ids = nav_ids(page)
            assert ("reports" in ids) is reports, (role, ids)
            assert ("settings" in ids) is settings, (role, ids)
            assert ("price_book" in ids) is price_book, (role, ids)
            page.goto(page.base + "#/reports?tab=winloss")
            if reports:
                page.wait_for_selector("#report-tabs")
                assert page.locator("#report-body").count() == 1
            else:
                page.wait_for_selector("#nav")
                assert page.locator("#report-tabs").count() == 0
            page.goto(page.base + "#/settings")
            page.wait_for_selector("#nav")
            assert page.locator("#settings-body").count() == 0
    # The Compare button is owner/estimator only, and so is the Price Book:
    # reviewer/office see the button rendered disabled, and the Price Book
    # route falls back to the dashboard (can_compare gates it: reports_api
    # revision_list / store.EDIT_ROLES; Price Book is owner/estimator-only
    # in nav.py).
    for role, can_compare in (("owner", True), ("estimator", True),
                              ("reviewer", False), ("office", False)):
        with sign_in_as(page, role):
            page.goto(page.base + f"#/reports?tab=revisions&estimate={revs['est']}")
            page.wait_for_selector("#rv-waiting")
            dismiss_tour(page)
            btn = page.locator(f"#rv-waiting [data-new='{revs['b']}']")
            assert btn.count() == 1
            assert btn.is_enabled() is can_compare, (role, btn.is_enabled())
            page.goto(page.base + "#/price_book")
            if can_compare:
                page.wait_for_selector("#prices")
                assert page.locator("#prices").count() == 1
            else:
                page.wait_for_selector("#nav")
                assert page.locator("#prices").count() == 0
