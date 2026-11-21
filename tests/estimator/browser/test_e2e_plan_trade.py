"""E2E (Playwright, headless): the plan-set page defaults its trade to the estimate's, and
"All trades" switches a sheet for every takeoff at once (2026-11-19, David).

David opened the panel schematic's plan-set page on an electrical estimate and the
"Measure for" dropdown said Concrete — app.js hardcoded it. Now the first load defaults
to the estimate's first trade (then the first sheet's discipline, then Concrete), and an
"All trades" entry covers the reference-sheet case: one switch per sheet for every
takeoff trade, mixed showing as indeterminate, a click on mixed switching it off.
"""
import pytest

from e2e_helpers import CTX, dismiss_tour
from estimator.director import engine as director
from estimator.drawing_model import engine, store
from estimator.estimating import service
from estimator.takeoff import sheet_trades
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape


@pytest.fixture
def trade_plans(db, tmp_path):
    """Three estimates, each with one read two-sheet plan set:
    - elec_first: trades picked electrical-then-concrete;
    - no_trades_disc: no trades picked, first sheet discipline electrical;
    - no_trades_none: no trades picked, no discipline anywhere."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    pages = [plan(lt, ll + shape("recept", 5, 5)), plan(lt, ll + shape("recept", 9, 9))]
    out = {}
    for key, name, trades, disc in (
            ("elec_first", "House rewire", ["electrical", "concrete"], "electrical"),
            ("no_trades_disc", "House rewire 2", None, "electrical"),
            ("no_trades_none", "House rewire 3", None, None)):
        est = service.create_estimate(db, CTX, name)
        ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / f"{key}.pdf", pages)),
                          confirm=True)["plan_set_id"]
        engine.start(db, CTX, ps, confirm=True)
        if trades:
            director.set_project_trades(db, CTX, est["id"], trades)
        sheets = store.sheets(db, CTX, ps)["sheets"]
        if disc:
            db.execute("UPDATE sheets SET discipline = ? WHERE id = ?", (disc, sheets[0]["id"]))
        # No trade discipline anywhere: the engine assigns one from the legend, so set a
        # discipline that is not a trade (structural) on both sheets.
        else:
            db.execute("UPDATE sheets SET discipline = 'structural' WHERE plan_set_id = ?", (ps,))
        db.commit()
        out[key] = {"est": est["id"], "ps": ps, "sheets": [s["id"] for s in sheets]}
    return out


def _trade_value(page):
    return page.evaluate("() => document.querySelector('#plan-trade').value")


def test_E2E_plan_set_defaults_to_the_estimate_first_trade(page, trade_plans):
    page.goto(page.base + f"#/plan-sets/{trade_plans['elec_first']['ps']}")
    page.wait_for_selector("#plan-trade")
    dismiss_tour(page)
    assert _trade_value(page) == "electrical"


def test_E2E_no_trades_defaults_to_the_first_sheet_discipline(page, trade_plans):
    page.goto(page.base + f"#/plan-sets/{trade_plans['no_trades_disc']['ps']}")
    page.wait_for_selector("#plan-trade")
    dismiss_tour(page)
    assert _trade_value(page) == "electrical"


def test_E2E_no_trades_no_discipline_defaults_to_concrete(page, trade_plans):
    page.goto(page.base + f"#/plan-sets/{trade_plans['no_trades_none']['ps']}")
    page.wait_for_selector("#plan-trade")
    dismiss_tour(page)
    assert _trade_value(page) == "concrete"


def test_E2E_all_trades_toggle_mixed_click_switches_everything_off_then_on(page, db, trade_plans):
    seed = trade_plans["elec_first"]
    sheet = seed["sheets"][0]
    # Mixed to start with: off for Concrete only, on for every other trade.
    sheet_trades.set_active(db, CTX, sheet, "concrete", False)
    db.commit()
    page.goto(page.base + f"#/plan-sets/{seed['ps']}")
    page.wait_for_selector("#plan-trade")
    dismiss_tour(page)
    page.select_option("#plan-trade", "all")
    toggle = f".sheet-trade-toggle[data-sheet='{sheet}']"
    # The page re-renders with the All-trades view: the toggle shows mixed (indeterminate).
    page.wait_for_function(f"() => {{ const b = document.querySelector(\"{toggle}\");"
                           " return b && b.indeterminate; }", timeout=20000)
    trades = page.evaluate("() => [...document.querySelectorAll('#plan-trade option')]"
                           ".map(o => o.value).filter(v => v !== 'all')")
    assert len(trades) > 1
    # Clicking a mixed sheet switches it off for every trade: the " off" badge appears only
    # once the per-trade saves have landed, so waiting on it proves the writes reached the server.
    page.click(toggle)
    page.wait_for_function(f"() => {{ const b = document.querySelector(\"{toggle}\");"
                           " const s = b && b.nextElementSibling; return s && !s.hidden; }", timeout=20000)
    rows = {r[0]: bool(r[1]) for r in db.execute(
        "SELECT module_id, active FROM sheet_trade_active WHERE sheet_id = ?", (sheet,))}
    assert rows == {t: False for t in trades}
    # Click again: back on for every trade, and the badge hides again.
    page.click(toggle)
    page.wait_for_function(f"() => {{ const b = document.querySelector(\"{toggle}\");"
                           " const s = b && b.nextElementSibling; return b && b.checked && s && s.hidden; }",
                           timeout=20000)
    rows = {r[0]: bool(r[1]) for r in db.execute(
        "SELECT module_id, active FROM sheet_trade_active WHERE sheet_id = ?", (sheet,))}
    assert rows == {t: True for t in trades}
