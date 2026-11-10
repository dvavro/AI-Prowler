"""Coder 2 Sprint 19 E2E GUI tests (Playwright, human mode): revision clouds + Price Book file import.

    run_tests_estimator.bat browser -k E2E_S19 [--human]

See tests/estimator/E2E_GUI_TEST_PLAN.md.
"""
import pytest

from browser_helpers import type_in
from e2e_helpers import CTX, PLAN, compare_in_browser, dismiss_tour, make_revs, xlsx_supplier
from estimator.context import personal_context
from estimator.drawing_model import revisions, store
from estimator.estimating import service
from estimator.takeoff import measurements as m

CSV_TEXT = "Item Code,Description,Unit,Unit Price\npw_driveway_sqft,Driveway,sqft,0.19\nbogus,Nothing like this,ea,5\n"
CSV_22 = "Item Code,Description,Unit,Unit Price\npw_driveway_sqft,Driveway,sqft,0.22\nbogus,Nothing like this,ea,5\n"
KEY = "pw_driveway_sqft"


@pytest.fixture
def revs(db, tmp_path):
    return make_revs(db, tmp_path)


def _cloud_plan():
    objs = [{"viewport": "plan", "kind": "polygon", "label": "SLAB", "source": "cad",
             "geometry": {"type": "polygon", "points": [[1, 1], [6, 1], [6, 5], [1, 5]]}},
            {"viewport": "plan", "kind": "polyline", "label": "DELTA 1", "layer": "REVISION",
             "source": "cad", "geometry": {"type": "polyline", "points": [[2, 2], [4, 2], [4, 3]]}}]
    return {"sheets": [{"page_no": 1, "sheet_no": "A-101", "title": "PLAN", "discipline": "architectural",
                        "units": "paper_in", "width": 36, "height": 24,
                        "viewports": [{"key": "plan", "label": "PLAN", "scale_note": "1/4\" = 1'-0\""}],
                        "objects": objs}]}


@pytest.fixture
def cloud_report(db, tmp_path):
    """A report whose only change is a revision cloud (marks alone mark the sheet changed)."""
    from e2e_helpers import _pdf
    est = service.create_estimate(db, CTX, "Cloud only")["id"]
    a = store.upload(db, CTX, est, _pdf(tmp_path / "cA.pdf", 1, "A"), confirm=True)["plan_set_id"]
    store.save_results(db, CTX, a, _cloud_plan(), "fake")
    b = store.upload(db, CTX, est, _pdf(tmp_path / "cB.pdf", 1, "B"), supersedes_plan_set_id=a,
                     confirm=True)["plan_set_id"]
    store.save_results(db, CTX, b, _cloud_plan(), "fake")
    db.commit()
    rep = revisions.compare(db, CTX, b, confirm=True)
    return rep["report_id"]


def open_import_box(page):
    page.click("#pb-import-box summary")
    page.wait_for_selector("#pb-csv")


# ------------------------------------------------------------------ M1: revision clouds overlay

def test_E2E_S19_M1_revision_clouds_overlay(page, revs, cloud_report):
    rid = compare_in_browser(page, page.base, revs)
    page.wait_for_selector("#rev-svg")
    dismiss_tour(page)
    assert "1" in page.inner_text("#rev-tiles")
    assert "Revision Clouds" in page.inner_text("#rev-tiles")
    # The cloud is drawn in purple on the overlay: one rect in the marks group.
    marks = page.locator("#rev-svg g.rev-marks rect")
    assert marks.count() == 1
    assert page.evaluate("() => getComputedStyle(document.querySelector('#rev-svg g.rev-marks rect')).fill") in (
        "rgb(124, 58, 237)", "#7c3aed")
    # The checkbox hides and shows it.
    page.uncheck("#rev-kinds input[data-kind=marks]")
    assert "hidden" in (page.get_attribute("#rev-svg g.rev-marks", "class") or "")
    page.check("#rev-kinds input[data-kind=marks]")
    assert "hidden" not in (page.get_attribute("#rev-svg g.rev-marks", "class") or "")
    # "Changes on this sheet" lists the cloud.
    page.click("#rev-items summary")
    page.wait_for_selector("#rev-items tbody tr[data-kind=marks]")
    assert "REV CLOUD" in page.inner_text("#rev-items tbody tr[data-kind=marks]")
    # The new sheet in Rev B is not a compared pair, so the picker lists only
    # the paired sheet; the new sheet is reported in the note below the overlay
    # (revisions.py per_sheet covers paired sheets only; reports.js lists fresh
    # sheets under "New sheets:").
    assert page.locator("#rev-sheet option").count() == 1
    assert "New sheets: E-102" in page.inner_text("body")
    # "Show Rev A (old)" shows the old sheet: the new-only cloud is gone there.
    page.select_option("#rev-sheet", index=0)
    page.wait_for_selector("#rev-flip")
    assert "Show Rev A (old)" in page.inner_text("#rev-flip")
    page.click("#rev-flip")
    page.wait_for_function("() => location.hash.includes('old=1')")
    # The flip re-renders after an async fetch; #rev-svg already exists in the
    # stale view, so wait for the re-rendered flip label before counting.
    page.wait_for_function("() => document.querySelector('#rev-flip')?.textContent?.includes('Show Rev B (new)')")
    assert page.locator("#rev-svg g.rev-marks rect").count() == 0
    assert "Show Rev B (new)" in page.inner_text("#rev-flip")
    # A clouds-only sheet still shows as changed.
    page.goto(page.base + f"#/revisions/{cloud_report}")
    # Same stale-render race: wait for this report's sheet in the picker.
    page.wait_for_function("() => document.querySelector('#rev-sheet')?.textContent?.includes('A-101')")
    assert page.locator("#rev-svg g.rev-marks rect").count() == 1
    assert "1 marks" in page.inner_text("#rev-sheet") or "marks" in page.inner_text("#rev-sheet")


# ------------------------------------------------------------------ M7: Price Book file import

def test_E2E_S19_M7_price_book_file_import(page, db, tmp_path):
    page.goto(page.base + "#/price_book?module=pressure_washing")
    page.wait_for_selector("#prices")
    dismiss_tour(page)
    # Multi-sheet workbook: the sheet picker appears; Cover previews its own columns.
    xlsx = xlsx_supplier(tmp_path)
    open_import_box(page)
    page.set_input_files("#pb-file", xlsx)
    page.wait_for_function("() => document.querySelector('#pb-import-message').textContent.includes('row(s)')")
    assert "suppliers.xlsx" in page.inner_text("#pb-import-message")
    assert page.locator("#pb-sheet").is_visible()
    assert page.locator("#pb-sheet option").count() == 2
    page.select_option("#pb-sheet", "Cover")
    page.wait_for_function("() => document.querySelector('#pb-mapping').textContent.includes('Note')")
    page.select_option("#pb-sheet", "Prices")
    page.wait_for_function("() => document.querySelector('#pb-mapping select[data-field=cost]')?.value === 'Unit Price'")
    assert page.input_value("#pb-mapping select[data-field=price_key]") == "Item Code"
    page.click("#pb-import")
    page.wait_for_selector("#pb-confirm")
    page.click("#pb-confirm")
    page.wait_for_function("() => document.body.innerText.includes('Imported 1 price(s)')")
    page.evaluate("route()")
    page.wait_for_function("() => document.querySelector('#prices tr[data-key=pw_driveway_sqft] input.cost')?.value === '0.19'")
    # The staged file is gone after the import.
    from estimator.api import staging
    assert staging.count() == 0
    # Then a CSV file: same flow, and the new price saves.
    csv_path = tmp_path / "suppliers.csv"
    csv_path.write_text(CSV_22, encoding="utf-8")
    open_import_box(page)
    page.set_input_files("#pb-file", csv_path)
    page.wait_for_function("() => document.querySelector('#pb-csv').value.includes('0.22')")
    page.click("#pb-columns")
    page.wait_for_selector("#pb-mapping select[data-field=cost]")
    page.click("#pb-import")
    page.wait_for_selector("#pb-confirm")
    page.click("#pb-confirm")
    page.wait_for_function("() => document.body.innerText.includes('Imported 1 price(s)')")
    page.evaluate("route()")
    page.wait_for_function("() => document.querySelector('#prices tr[data-key=pw_driveway_sqft] input.cost')?.value === '0.22'")
    # Over 5 MB is refused, and so is a wrong extension.
    big = tmp_path / "big.xlsx"
    big.write_bytes(b"x" * (5 * 1024 * 1024 + 1))
    open_import_box(page)
    page.set_input_files("#pb-file", big)
    page.wait_for_function("() => document.querySelector('#pb-import-message').textContent.trim().length > 0")
    assert "5 MB" in page.inner_text("#pb-import-message")
    wrong = tmp_path / "suppliers.pdf"
    wrong.write_bytes(b"%PDF-1.4 fake")
    page.set_input_files("#pb-file", wrong)
    page.wait_for_function("() => document.querySelector('#pb-import-message').textContent.includes('cannot be used')")
    # Pasting still works after the file flows.
    type_in(page, "#pb-csv", CSV_TEXT.replace("0.19", "0.30"))
    page.click("#pb-columns")
    page.wait_for_selector("#pb-mapping select[data-field=cost]")
    page.click("#pb-import")
    page.wait_for_selector("#pb-confirm")
    page.click("#pb-confirm")
    page.wait_for_function("() => document.body.innerText.includes('Imported 1 price(s)')")
    page.evaluate("route()")
    page.wait_for_function("() => document.querySelector('#prices tr[data-key=pw_driveway_sqft] input.cost')?.value === '0.30'")
