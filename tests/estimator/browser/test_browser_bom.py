"""Estimates screen, a trade's Bill of Materials (2026-11-20, David: "there is no total, please add one, also there is no
panel"): the list shows its material total in the summary and under the table, the main panel and meter base are on it,
and fixtures the owner supplies are not (only the labor to hang and wire them is on the quote).

    browser_upload.bat tests\\estimator\\browser\\test_browser_bom.py
"""
from estimator.context import personal_context
from estimator.estimating import bom, quick, service

CTX = personal_context()


def test_bom_total_panel_and_owner_fixtures(page, db):
    e = service.create_estimate(db, CTX, "Panel and fixtures")
    e = quick.answer(db, CTX, e["id"], "electrical",
                     {"outlets": 10, "switches": 4, "lights": 6, "fans": 2, "main_panels": 1}, e["rev"])
    db.commit()
    sec = next(s for s in e["sections"] if s["module_id"] == "electrical")
    items = bom.bom_for_section(db, "default", sec["id"])
    total = sum(round(i["unit_cost_cents"] * float(i["order_quantity"])) for i in items)
    money = "$" + format(total / 100, ",.2f")

    page.goto(page.base + f"#/estimates/{e['id']}")
    summary = page.locator("#bom-electrical summary")
    summary.wait_for()
    assert money in summary.inner_text()                                    # the total, even while it's folded
    summary.click()
    foot = page.locator("#bom-total-electrical")
    assert "Total materials" in foot.inner_text() and money in foot.inner_text()
    rows = page.locator("#bom-table-electrical tbody tr")
    keys = [rows.nth(i).get_attribute("data-bom-item") for i in range(rows.count())]
    assert "el_main_panel_ea" in keys and "el_meter_base_ea" in keys        # the panel is on the list now
    assert "el_light_ceiling_ea" not in keys and "el_fan_unit_ea" not in keys   # the owner's fixtures aren't

    # The quote's lines: hanging and wiring the owner's fixtures is labor; the fixtures are listed at $0.
    text = page.inner_text("body")
    assert "Hang and wire light fixtures and fans" in text and "supplied by the owner" in text
    assert "null" not in text

    # The CSV carries the total too.
    with page.expect_download() as dl:
        page.click("#bom-csv-electrical")
    csv = open(dl.value.path(), encoding="utf-8").read()
    assert csv.splitlines()[-1].startswith("Total,") and csv.splitlines()[-1].endswith(format(total / 100, ".2f"))
