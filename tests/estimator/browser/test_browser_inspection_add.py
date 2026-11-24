"""Estimate page, 🔍 Inspection review: "Add to estimate" (2026-11-23, David: "When I review the inspection and click add
to the estimate, nothing happens"). The AI had named items that aren't in the price book, and the refusal showed at the
top of the page. Now: an item in the price book adds in one click; one that isn't opens a picker under its row - the
closest item chosen when there's a close one, or a typed price - and errors show beside the button.

    browser_upload.bat tests\\estimator\\browser\\test_browser_inspection_add.py
"""
import json

from estimator.context import personal_context
from estimator.estimating import quick, service

CTX = personal_context()
NOW = "2026-11-23T10:00:00+00:00"


def _item(iid, desc, key, qty, what):
    return {"id": iid, "description": desc, "code_ref": "250", "status": "missing", "note": "",
            "suggested_action": {"price_key": key, "quantity": qty, "unit": "ea", "description": what}}


def _estimate(db):
    e = service.create_estimate(db, CTX, "Shed inspection", address="1 Main St, New Smyrna Beach, FL 32168")
    e = quick.answer(db, CTX, e["id"], "electrical", {"outlets": 10, "switches": 2, "lights": 6, "gfci": 0}, e["rev"])
    checklist = [_item("gfci", "GFCI protection", "el_gfci_ea", 2, "GFCI outlets"),                  # in the book
                 _item("subpanel", "Neutral and ground separated in subpanels", "subpanel_100a", 1,  # close match
                       "100 Amp subpanel"),
                 _item("rods", "Grounding electrode system", "ground_rod", 2,                         # nothing close
                       "8 ft ground rods to the shed subpanel")]
    db.execute("INSERT INTO inspection_reviews (company_id, estimate_id, module_id, zip_code, jurisdiction_json,"
               " nec_edition, checklist_json, status, created_by, created_at) VALUES ('default', ?, 'electrical',"
               " '32168', '{}', '2020', ?, 'complete', 'owner', ?)", (e["id"], json.dumps(checklist), NOW))
    db.commit()
    return e["id"]


def _other_lines(db, eid):
    return [tuple(r) for r in db.execute(
        "SELECT li.description, li.quantity, li.unit_cost_cents, li.price_key FROM line_items li JOIN trade_sections"
        " ts ON ts.id = li.trade_section_id WHERE ts.estimate_id = ? AND ts.module_id = 'custom' ORDER BY li.id",
        (eid,))]


def test_add_from_the_inspection_review(page, db):
    eid = _estimate(db)
    page.goto(page.base + f"#/estimates/{eid}")
    page.wait_for_selector("#inspection-checklist-electrical")
    card = page.inner_text("#inspection-checklist-electrical")
    assert "(not in your price book)" in card and "$22.00 / ea" in card          # the GFCI outlet's own price shows

    # in the price book: one click
    page.click("[data-inspection-add=gfci]")
    page.wait_for_function(f"() => !!document.querySelector('#inspection-checklist-electrical')")
    page.wait_for_timeout(800)
    assert ("GFCI outlets", "2", 2200, "el_gfci_ea") in _other_lines(db, eid)

    # not in the book, a close item: the picker opens under the row with it chosen
    page.wait_for_selector("[data-inspection-add=subpanel]")
    assert page.inner_text("[data-inspection-add=subpanel]") == "Add to estimate…"
    page.click("[data-inspection-add=subpanel]")
    page.wait_for_selector("[data-inspection-pick=subpanel]:not([hidden])")
    assert page.input_value("[data-inspection-price=subpanel]") == "el_subpanel_100a_ea"
    page.click("[data-inspection-pick-go=subpanel]")
    page.wait_for_timeout(1200)
    assert any(r[3] == "el_subpanel_100a_ea" for r in _other_lines(db, eid))

    # nothing close: it starts on "type a price"; no price typed says so right there
    page.wait_for_selector("[data-inspection-add=rods]")
    page.click("[data-inspection-add=rods]")
    page.wait_for_selector("[data-inspection-pick=rods]:not([hidden])")
    assert page.input_value("[data-inspection-price=rods]") == ""
    page.click("[data-inspection-pick-go=rods]")
    assert "Type the unit cost" in page.inner_text("[data-inspection-pick=rods]")
    page.fill("[data-inspection-cost=rods]", "35")
    page.fill("[data-inspection-qty=rods]", "3")
    page.click("[data-inspection-pick-go=rods]")
    page.wait_for_timeout(1200)
    assert ("8 ft ground rods to the shed subpanel", "3", 3500, None) in _other_lines(db, eid)
