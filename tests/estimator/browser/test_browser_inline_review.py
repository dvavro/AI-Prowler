"""Measure screen, Measurements tab: reviewing an AI count without leaving the list (2026-11-19, David: "1 click
highlights the objects, no redirects needed, allows to change the count, allows to add/subtract and identify by
add/subtract a selected symbol in the drawing").

    browser_upload.bat tests\\estimator\\browser\\test_browser_inline_review.py
"""
import json

import pytest

from test_browser_count_highlight import CTX, cad_job, sel  # noqa: F401 - cad_job is a fixture


def _propose(db, estimate_id, feeds, qty, how):
    sheet = db.execute("SELECT s.id FROM sheets s JOIN plan_sets p ON p.id = s.plan_set_id WHERE p.estimate_id = ?",
                       (estimate_id,)).fetchone()[0]
    mid = db.execute(
        "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label, qty,"
        " unit, source_object_ids, calc_json, method, status, locked, proposed_by, created_at, updated_at)"
        " VALUES (?, ?, 'electrical', ?, ?, NULL, 'count', ?, ?, 'ea', '[]', ?, 'ai', 'proposed', 0, 'llm-takeoff',"
        " '2026-11-19T00:00:00+00:00', '2026-11-19T00:00:00+00:00')",
        (CTX.company_id, estimate_id, feeds, sheet, f"{feeds} (AI)", str(qty),
         json.dumps({"source": "llm", "auto_run_id": 1, "how": how}))).lastrowid
    db.commit()
    return mid


@pytest.fixture
def review_job(db, cad_job):  # noqa: F811
    est = cad_job["estimate_id"]
    fans = _propose(db, est, "fans", 4, "4 ceiling fans in the living areas")       # the AI said 4; the plan has 3
    dimmers = _propose(db, est, "dimmers", 1, "1 dimmer by the door")
    return {"estimate_id": est, "fans": fans, "dimmers": dimmers}


def test_review_in_the_list_with_the_drawing(page, db, review_job):
    page.goto(page.base + f"#/takeoffs/{review_job['estimate_id']}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.click("#bp-tab-list")
    # One click on the row: its 3 fans light up on the drawing and the card opens under the row - no other tab.
    page.click(f"#bp-rows li[data-mid='{review_job['fans']}']")
    page.wait_for_selector("#bp-review")
    assert sel(page) == 3
    assert page.get_attribute("#bp-tab-list", "class").split().count("active") == 1      # still the Measurements tab
    card = page.inner_text("#bp-review")
    assert "AI: 4 ea" in card and "4 ceiling fans" in card and "3 highlighted on the drawing" in card
    # 2026-11-20 (David): the AI said 4, the drawing shows 3 - the count starts at the 3 lit up on the drawing.
    assert page.input_value("#bp-review-qty") == "3"
    assert page.is_hidden("#bp-review-use-highlighted")                # already the highlighted number
    # The legend's fan lights up blue, to compare (and isn't counted).
    assert "Blue" in page.inner_text("#bp-review-legend")
    assert page.evaluate("() => document.querySelectorAll('#bp-viewer .legend-ref').length") == 1
    legend_oid = page.evaluate("() => +document.querySelector('#bp-viewer .legend-ref').getAttribute('data-oid')")
    assert page.evaluate(f"() => RV.symbolList.some(o => o.id === {legend_oid})") is False
    # Clicking it doesn't put it on the count.
    page.locator(f"#bp-viewer [data-oid='{legend_oid}']").click(force=True)
    assert page.input_value("#bp-review-qty") == "3"
    # − / + set a different count, and "Use the 3 highlighted" puts it back.
    page.click("#bp-review-plus")
    assert page.input_value("#bp-review-qty") == "4"
    page.click("#bp-review-use-highlighted")
    assert page.input_value("#bp-review-qty") == "3"
    # A symbol clicked on the drawing comes off the count (and its highlight goes); clicked again, it's back.
    oid = page.evaluate("() => RV.symbolList[0].id")
    page.locator(f"#bp-viewer [data-oid='{oid}']").click(force=True)
    page.wait_for_function("() => document.querySelector('#bp-review-qty').value === '2'")
    assert sel(page) == 2 and "2 highlighted" in page.inner_text("#bp-review")
    page.locator(f"#bp-viewer [data-oid='{oid}']").click(force=True)
    page.wait_for_function("() => document.querySelector('#bp-review-qty').value === '3'")
    assert sel(page) == 3
    # − / + for what isn't on the drawing.
    page.click("#bp-review-plus")
    page.click("#bp-review-minus")
    assert page.input_value("#bp-review-qty") == "3"
    # The AI Log opens in a new browser tab: this screen stays put.
    assert page.get_attribute("#bp-review-ai-log", "target") == "_blank"
    # ✓ Approve 3 ea: saved and approved in one click, then on to the next one to review (the dimmer).
    assert "Approve 3" in page.inner_text("#bp-review-approve")
    page.click("#bp-review-approve")
    page.wait_for_selector(f"#bp-rows li[data-mid='{review_job['dimmers']}'] #bp-review", timeout=20000)
    row = db.execute("SELECT qty, status FROM measurements WHERE id = ?", (review_job["fans"],)).fetchone()
    assert float(row["qty"]) == 3 and row["status"] == "approved"
    # Close: the highlight goes and the card closes.
    page.click("#bp-review-close")
    page.wait_for_selector("#bp-review", state="detached")
    assert sel(page) == 0


def test_change_your_mind_reject_approve_again_and_change(page, db, review_job):
    """2026-11-20 (David): "the user should be free to change/reapprove/reject and not be restricted to change his
    mind" - a rejected count can be approved again, an approved one changed or rejected."""
    fans = review_job["fans"]
    status = lambda: db.execute("SELECT qty, status FROM measurements WHERE id = ?", (fans,)).fetchone()  # noqa: E731
    page.goto(page.base + f"#/takeoffs/{review_job['estimate_id']}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.click("#bp-tab-list")
    row = f"#bp-rows li[data-mid='{fans}']"
    # Reject it.
    page.click(row)
    page.wait_for_selector("#bp-review-reject")
    page.click("#bp-review-reject")
    page.wait_for_function(f"() => !document.querySelector(\"{row} #bp-review\")", timeout=20000)
    assert status()["status"] == "rejected"
    # Open it again (Show: All lists the rejected ones): it says it's rejected and can be approved again.
    if page.locator("#bp-review").count():
        page.click("#bp-review-close")
    page.select_option("#bp-filter", "all")
    page.click(row)
    page.wait_for_selector(f"{row} #bp-review")
    assert "Rejected" in page.inner_text("#bp-review-state")
    assert page.locator("#bp-review-reject").count() == 0
    assert page.input_value("#bp-review-qty") == "3"                  # starts at the 3 lit up on the drawing
    assert "Approve again 3" in page.inner_text("#bp-review-approve")
    page.click("#bp-review-approve")
    page.wait_for_function(f"() => !document.querySelector(\"{row} #bp-review\")", timeout=20000)
    r = status()
    assert r["status"] == "approved" and float(r["qty"]) == 3
    # Approved: change the count and save it.
    if page.locator("#bp-review").count():
        page.click("#bp-review-close")
    page.click(row)
    page.wait_for_selector(f"{row} #bp-review")
    assert "Approved" in page.inner_text("#bp-review-state")
    assert page.is_disabled("#bp-review-approve")                     # nothing changed yet
    page.click("#bp-review-plus")
    assert "Save 4" in page.inner_text("#bp-review-approve")
    page.click("#bp-review-approve")
    page.wait_for_function(f"() => !document.querySelector(\"{row} #bp-review\")", timeout=20000)
    r = status()
    assert r["status"] == "approved" and float(r["qty"]) == 4
    # And reject the approved one.
    if page.locator("#bp-review").count():
        page.click("#bp-review-close")
    page.click(row)
    page.wait_for_selector(f"{row} #bp-review-reject")
    page.click("#bp-review-reject")
    page.wait_for_function(f"() => !document.querySelector(\"{row} #bp-review\")", timeout=20000)
    assert status()["status"] == "rejected"
