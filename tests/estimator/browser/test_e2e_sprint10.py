"""Coder 2 Sprint 10 E2E GUI tests (Playwright, human mode): Symbol Recognition Engine v1, Jobs board.

    run_tests_estimator.bat browser -k E2E_S10 [--human]

M5: the plan set page's symbol counts table (and the legend Found column) and the
    symbols in their trade's layer in Blueprint Review.
M6: the Jobs board with a plan-takeoff job - progress line, links work (owner + field).
M1-M4/M7 stay manual (real-plan accuracy / live AI). See tests/estimator/E2E_GUI_TEST_PLAN.md.
"""
from datetime import datetime, timezone

import pytest

from e2e_helpers import CTX, dismiss_tour, sign_in_as
from estimator.drawing_model import engine, store
from estimator.estimating import service
from estimator.takeoff import measurements
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape


@pytest.fixture
def power(db, tmp_path):
    """A power plan with a legend (receptacle, GFCI, special device): 2 duplex
    receptacles, 1 GFCI (GFI code beside it) and 1 unidentified special device.
    Same seed as tests/estimator/webapp/test_web_sprint10.py (C2S10-W01/W04)."""
    est = service.create_estimate(db, CTX, "Smith house")
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("recept", "GFI", "DUPLEX RECEPTACLE, GFCI"),
                     ("flag", None, "SPECIAL DEVICE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("flag", 12, 8)
    pdf = make_pdf(tmp_path / "power.pdf", [plan(lt + [(7.15, 4.95, 7, "GFI")], lines)])
    ps = store.upload(db, CTX, est["id"], str(pdf), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


def _counts_row(page, item):
    """The counts-table row for one item type, as its cell texts."""
    row = page.locator(f"#plan-symbols table.symbol-counts tbody tr[data-item={item}]")
    assert row.count() == 1, item
    cells = row.locator("td")
    return [cells.nth(i).inner_text() for i in range(cells.count())]


def _job(db, estimate_id, lane, stage, waiting_on="user"):
    """A Director job, as in tests/estimator/webapp/test_web_sprint10.py."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return db.execute("INSERT INTO director_jobs (company_id, estimate_id, lane, stage, state, waiting_on, request_text,"
                      " created_at, updated_at) VALUES ('default', ?, ?, ?, 'waiting_on_user', ?, ?, ?, ?)",
                      (estimate_id, lane, stage, waiting_on, f"{lane} job", now, now)).lastrowid


# ------------------------------------------------------------------ M5: counts table; symbols in trade layer

def test_E2E_S10_M5_counts_table_and_layers(page, power):
    ps, eid = power["plan_set_id"], power["estimate_id"]
    page.goto(page.base + f"#/plan-sets/{ps}")
    page.wait_for_selector("#plan-symbols")
    dismiss_tour(page)
    # The counts table: 4 symbols, by type and sheet.
    assert "4 symbol(s)" in page.inner_text("#plan-symbols")
    assert "E-101" in page.inner_text("#plan-symbols thead")
    assert _counts_row(page, "duplex_receptacle")[2] == "2"
    assert _counts_row(page, "duplex_receptacle_gfci")[2] == "1"
    unknown = _counts_row(page, "unknown")
    assert unknown[2] == "1" and "needs a person" in unknown[0]
    assert unknown[3] == "1"  # to check
    # The legend tables gain a Found column with the same counts.
    found = {}
    for row in page.locator(".legend-entries tbody tr").all():
        cells = row.locator("td")
        found[cells.nth(1).inner_text()] = cells.nth(4).inner_text()
    assert found == {"DUPLEX RECEPTACLE": "2", "DUPLEX RECEPTACLE, GFCI": "1", "SPECIAL DEVICE": "1"}
    # Blueprint Review: the symbols sit in the Electrical layer, 4 of them.
    page.goto(page.base + f"#/takeoffs/{eid}")
    page.wait_for_selector("#bp-viewer")
    dismiss_tour(page)
    page.click("#bp-tab-layers")
    page.wait_for_selector("#bp-layers tr[data-group=electrical]")
    layer = page.inner_text("#bp-layers tr[data-group=electrical]")
    assert "Electrical" in layer and "4" in layer
    assert page.locator("#bp-pane-layers").is_visible()
    # ... and the Symbols tab counts them by type.
    page.click("#bp-tab-symbols")
    page.wait_for_selector("#bp-symbol-types")
    assert "2 found" in page.inner_text("#bp-symbol-types")  # duplex receptacles


# ------------------------------------------------------------------ M6: Jobs board plan-takeoff job; links work

def test_E2E_S10_M6_jobs_board_links(page, power, db):
    eid, ps = power["estimate_id"], power["plan_set_id"]
    jid = _job(db, eid, "full_takeoff", "takeoff")
    other = service.create_estimate(db, CTX, "Fence")
    _job(db, other["id"], "quick_quote", "approve", waiting_on="customer")
    # One proposed measurement, so the takeoff line (and its Blueprint Review link) renders.
    sheet = store.sheets(db, CTX, ps)["sheets"][0]
    sym = store.objects(db, CTX, sheet_id=sheet["id"], kind="symbol")["objects"]
    measurements.propose(db, CTX, eid, "electrical", [o["id"] for o in sym],
                         kind="count", label="symbols", confirm=True)
    db.commit()
    page.goto(page.base + "#/jobs")
    page.wait_for_selector("#jobs-summary")
    dismiss_tour(page)
    summary = page.inner_text("#jobs-summary")
    assert "Plan takeoffs: 1" in summary and "1 waiting on you" in summary
    row = page.locator(f"table[data-lane=full_takeoff] tr[data-id='{jid}']")
    assert row.count() == 1
    assert "step 3 of 8" in row.inner_text() and "Price approved quantities" in row.inner_text()
    progress = row.locator(".job-progress").inner_text()
    assert "📐 1 sheet(s)" in progress and "🔣 4 symbol(s)" in progress and "1 to check" in progress
    assert "📏 0 approved" in progress and "1 waiting" in progress
    # The links work for the owner: project, Blueprint Review, estimate.
    row.locator(f".job-progress a[href='#/projects/{eid}']").click()
    page.wait_for_url(f"**#/projects/{eid}")
    page.wait_for_function("() => document.body.innerText.includes('Plans and documents')")
    page.goto(page.base + "#/jobs")
    page.wait_for_selector("#jobs-summary")
    row = page.locator(f"table[data-lane=full_takeoff] tr[data-id='{jid}']")
    row.locator(f".job-progress a[href='#/takeoffs/{eid}']").click()
    page.wait_for_url(f"**#/takeoffs/{eid}")
    page.wait_for_selector("#bp-viewer")
    page.goto(page.base + "#/jobs")
    page.wait_for_selector("#jobs-summary")
    row = page.locator(f"table[data-lane=full_takeoff] tr[data-id='{jid}']")
    assert row.locator(f".job-progress a[href='#/estimates/{eid}']").count() == 1
    # Field staff get the plans link but no takeoffs link.
    with sign_in_as(page, "field"):
        page.goto(page.base + "#/jobs")
        page.wait_for_selector("#jobs-summary")
        frow = page.locator(f"table[data-lane=full_takeoff] tr[data-id='{jid}']")
        assert frow.locator(f".job-progress a[href='#/projects/{eid}']").count() == 1
        assert frow.locator(".job-progress a[href^='#/takeoffs/']").count() == 0
