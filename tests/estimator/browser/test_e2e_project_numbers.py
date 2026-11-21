"""E2E (Playwright, headless): the Projects list # column shows the row's position
in the displayed list (1, 2, 3...), not the global estimate id (2026-11-19, David).

Same treatment as the plan-set numbering fix: the # cell is positional within
the rows actually rendered, while the row link and data-id keep the real id.
estimateTable is shared with the dashboard's Recent list, so both lists are
checked — each numbers within its own rendered rows.
"""
import pytest

from e2e_helpers import CTX, dismiss_tour
from estimator.estimating import service


@pytest.fixture
def three_projects(db):
    """Three estimates, created in order — ids 1, 2, 3 in the fresh sandbox DB."""
    ids = [service.create_estimate(db, CTX, name)["id"]
           for name in ("Alpha job", "Beta job", "Gamma job")]
    db.commit()
    return ids


def _table_rows(page):
    """(number, data-id, link href) per rendered row, in displayed order."""
    return page.evaluate("""() => [...document.querySelectorAll("table.list tbody tr")].map(tr => [
        tr.cells[0].textContent.trim(),
        tr.dataset.id,
        tr.querySelector("td a").getAttribute("href")])""")


def _assert_positional(rows, ids):
    # Newest first (ORDER BY updated_at DESC, id DESC): Gamma, Beta, Alpha.
    assert [r[1] for r in rows] == [str(i) for i in reversed(ids)]
    # The # column counts positions in the displayed list, not ids.
    assert [r[0] for r in rows] == ["1", "2", "3"]
    # Links still point at the real estimate ids.
    assert [r[2] for r in rows] == [f"#/projects/{r[1]}" for r in rows]


def test_E2E_projects_list_numbers_follow_displayed_order(page, three_projects):
    page.goto(page.base + "#/projects")
    page.wait_for_selector("table.list tbody tr")
    dismiss_tour(page)
    _assert_positional(_table_rows(page), three_projects)


def test_E2E_dashboard_recent_numbers_follow_displayed_order(page, three_projects):
    page.goto(page.base + "#/dashboard")
    page.wait_for_selector("table.list tbody tr")
    dismiss_tour(page)
    _assert_positional(_table_rows(page), three_projects)
