"""E2E (Playwright, human mode): a new project asks which trades it quotes (2026-11-14, David).

One project can quote several trades; each gets its own "Price ..." step and they go out in one quote.
"""
from browser_helpers import type_in
from e2e_helpers import CTX, dismiss_tour
from estimator.estimating import service


def test_E2E_new_project_picks_its_trades(page):
    page.goto(page.base + "#/projects")
    page.wait_for_selector("#new-project #new-trades input[data-trade='concrete']")
    dismiss_tour(page)
    type_in(page, "#new-title", "NSB Shed slab test3")
    # No trade ticked: it asks for one and makes nothing.
    page.click("#new-create")
    page.wait_for_selector("#new-message .error")
    assert "at least one trade" in page.inner_text("#new-message")
    page.check("#new-trades input[data-trade='concrete']")
    page.check("#new-trades input[data-trade='framing']")
    page.click("#new-create")
    page.wait_for_url("**#/projects/*")
    page.wait_for_selector("#director-todo li[data-key='price_framing']")
    todo = page.inner_text("#director-todo")
    assert "Concrete" in todo and "Framing" in todo
    assert page.locator("#director-todo li[data-key='price_concrete'] a").count() == 1
    # The Trades tile counts the picked trades, not only priced ones (2026-11-15, David).
    assert page.inner_text("#tile-trades .num") == "2"
    assert "0 priced" in page.inner_text("#tile-trades .lbl").lower()
    # The trades can be changed later: take framing off, then add plumbing; the tile follows.
    page.click("#director-trades-edit > summary")
    page.uncheck("#director-trades input[data-trade='framing']")
    page.click("#director-trades-save")
    page.wait_for_function("() => !document.querySelector(\"#director-todo li[data-key='price_framing']\")")
    assert page.locator("#director-todo li[data-key='price_concrete']").count() == 1
    assert page.inner_text("#tile-trades .num") == "1"
    page.click("#director-trades-edit > summary")
    page.check("#director-trades input[data-trade='plumbing']")
    page.click("#director-trades-save")
    page.wait_for_selector("#director-todo li[data-key='price_plumbing']")
    assert page.inner_text("#tile-trades .num") == "2"


def test_E2E_project_without_trades_asks_on_its_page(page, db):
    est = service.create_estimate(db, CTX, "Made elsewhere", address="1 Main St")
    db.commit()
    page.goto(page.base + f"#/projects/{est['id']}")
    page.wait_for_selector("#director-trades input[data-trade='drywall']")
    dismiss_tour(page)
    assert "Pick the trades" in page.inner_text("#director-say")
    page.click("#director-trades-save")                                   # nothing ticked
    assert "at least one trade" in page.inner_text("#director-message")
    page.check("#director-trades input[data-trade='drywall']")
    page.check("#director-trades input[data-trade='painting']")
    page.click("#director-trades-save")
    page.wait_for_selector("#director-todo li[data-key='price_painting']")
    assert page.locator("#director-trades-edit").count() == 1            # now tucked away under "Change the trades"
