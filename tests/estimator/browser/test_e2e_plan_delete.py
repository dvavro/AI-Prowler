"""Plan-set delete buttons on the two list surfaces (Playwright, headless).

    run_tests_estimator.bat browser -k plan_delete [--human]

2026-11-18, David: the plan-set page had the only Remove button — the Plans list
(#/plans) and the project page's plans table had no way to delete an uploaded plan.
Both list surfaces now carry a per-row delete button using the same ask-first
endpoint as the detail page (POST /plan-sets/<id>/remove).

P1: the Plans list row's delete button asks first, and confirming removes the plan
    set; deleting the last one shows the empty state. Clicking it does not navigate
    to the plan-set page (the row itself navigates).
P2: the project page's plans table has the same button; confirming removes the plan
    set and the table shows the empty state.
"""
import pytest

from e2e_helpers import CTX, _pdf, dismiss_tour
from estimator.drawing_model import store
from estimator.estimating import service


@pytest.fixture
def one_plan(db, tmp_path):
    """One estimate with one uploaded (unread) plan set."""
    est = service.create_estimate(db, CTX, "Smith house")["id"]
    ps = store.upload(db, CTX, est, _pdf(tmp_path / "smith.pdf", 1, "S"), confirm=True)["plan_set_id"]
    db.commit()
    return {"estimate_id": est, "plan_set_id": ps}


def test_E2E_plan_delete_from_plans_list(page, one_plan):
    ps = one_plan["plan_set_id"]
    page.goto(page.base + "#/plans")
    page.wait_for_selector("#plan-sets")
    dismiss_tour(page)
    row = page.locator(f"#plan-sets tbody tr[data-id='{ps}']")
    assert row.count() == 1
    btn = row.locator("[data-remove-plan-set]")
    assert btn.count() == 1
    btn.click()
    # Asking first: the server's question names the file and what goes with it —
    # and the click did not navigate away to the plan-set page.
    page.wait_for_selector("#plan-remove-confirm-box")
    box = page.inner_text("#plan-remove-confirm-box")
    assert "smith.pdf" in box
    assert "can't be undone" in box
    assert page.url.endswith("#/plans")
    page.click("#plan-remove-confirm")
    # The last plan set is gone: the table is replaced by the empty state.
    page.wait_for_selector("#plans-empty")
    assert page.locator("#plan-sets").count() == 0
    assert "No plans yet" in page.inner_text("#plans-empty")


def test_E2E_plan_delete_from_project_page(page, one_plan):
    ps, eid = one_plan["plan_set_id"], one_plan["estimate_id"]
    page.goto(page.base + f"#/projects/{eid}")
    page.wait_for_selector("#plans")
    dismiss_tour(page)
    btn = page.locator(f"#plans [data-remove-plan-set='{ps}']")
    assert btn.count() == 1
    btn.click()
    page.wait_for_selector("#plan-remove-confirm-box")
    box = page.inner_text("#plan-remove-confirm-box")
    assert "smith.pdf" in box
    assert "can't be undone" in box
    page.click("#plan-remove-confirm")
    page.wait_for_selector("#plans-empty")
    assert page.locator("#plans").count() == 0
    assert "No plans yet" in page.inner_text("#plans-empty")
