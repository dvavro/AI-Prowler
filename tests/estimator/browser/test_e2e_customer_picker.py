"""E2E (Playwright, human mode): "Make it a job in AI-Prowler…" asks who the customer is (2026-11-14).

    coder2_scratch\\browser_failed.bat style:  pytest tests\\estimator\\browser -k customer_picker

Pick an existing AI-Prowler customer (no new customer is made), or fill in a new one like the Jobs app's form.
AI-Prowler's tools are a stand-in host (tests/estimator/conftest.py FakeHost) with a small customer list.
"""
import pytest

from browser_helpers import answer_yes, type_in
from e2e_helpers import CTX, dismiss_tour
from estimator.bids import service as bids
from estimator.estimating import quick, service
from estimator.integrations import host
from estimator.modules.registry import ModuleRegistry

REG = ModuleRegistry().load()
ROWS = [
    {"customer_id": "CUST-2026-616", "customer_type": "Residential", "company_name": "AI Prowler LLC",
     "first_name": "David", "last_name": "Vavro", "phone": "555-0100", "email": "d@example.com",
     "street_address": "1500 Shadow Pines Dr", "city": "New Smyrna Beach", "state": "FL", "zip": "32168", "status": "Active"},
    {"customer_id": "CUST-2026-12", "customer_type": "Commercial", "company_name": "Panera Bread Daytona",
     "first_name": "", "last_name": "", "phone": "", "email": "", "street_address": "1 Beach St", "city": "Daytona",
     "state": "FL", "zip": "", "status": "Active"},
]


@pytest.fixture
def won_bid(db, fake_host):
    def find(query="", limit=25, customer_id=None):
        if customer_id:
            return [r for r in ROWS if r["customer_id"] == customer_id]
        words = query.lower().split()
        return [r for r in ROWS if all(w in " ".join(str(v) for v in r.values()).lower() for w in words)][:limit]
    host.set_host(dict(fake_host.funcs(), find_customers=find))
    e = service.create_estimate(db, CTX, "Shadow Pines clean")
    e = quick.answer(db, CTX, e["id"], "house_cleaning", {"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, e["rev"], REG)
    service.set_status(db, CTX, e["id"], e["rev"], "approved")
    b = bids.generate(db, CTX, e["id"], customer={"name": "AI Prowler LLC", "address": "1500 shadow pines dr"})
    bids.send(db, CTX, b["id"], to="d@example.com", confirm=True)
    bids.set_status(db, CTX, b["id"], "won")
    db.commit()
    return b["id"], fake_host


def _open_picker(page, bid_id):
    page.goto(page.base + f"#/bids/{bid_id}")
    page.wait_for_selector("#bid-convert")
    dismiss_tour(page)
    page.click("#bid-convert")
    page.wait_for_selector("#cust-picker")


def test_E2E_customer_picker_existing(page, won_bid):
    bid_id, fh = won_bid
    _open_picker(page, bid_id)
    # It starts on "Use an existing customer", searching for the quote's name.
    page.wait_for_selector("#cust-results [data-id='CUST-2026-616']")
    assert page.locator("#cust-results .cust-row").count() == 1
    # Searching narrows the list; clearing it shows everyone.
    type_in(page, "#cust-find", "panera")
    page.wait_for_selector("#cust-results [data-id='CUST-2026-12']")
    type_in(page, "#cust-find", "shadow")
    page.wait_for_selector("#cust-results [data-id='CUST-2026-616']")
    page.click("#cust-results [data-id='CUST-2026-616']")
    assert page.locator("#cust-picker").count() == 0
    # The yes/no question names the existing customer and makes no new one.
    page.wait_for_selector("#bid-confirm-box")
    q = page.inner_text("#bid-confirm-box")
    assert "a customer" not in q
    answer_yes(page, "bid")
    page.wait_for_function("() => document.body.innerText.includes('JOB-0001')")
    assert fh.named("create_customer") == []
    assert fh.named("create_job")[0]["updates"]["CustomerID"] == "CUST-2026-616"


def test_E2E_customer_picker_new_customer(page, won_bid):
    bid_id, fh = won_bid
    _open_picker(page, bid_id)
    page.click("#cust-tab-new")
    page.wait_for_selector("#cust-pane-new:not([hidden])")
    # The quote's name looks like a company, so it starts as a Commercial customer with that company.
    assert page.input_value("#cust-new-company") == "AI Prowler LLC"
    assert page.input_value("#cust-new-type") == "Commercial"
    # Nothing but a blank name? It says so and stays open.
    page.fill("#cust-new-company", "")
    page.click("#cust-new-use")
    assert "first or last name" in page.inner_text("#cust-new-message")
    type_in(page, "#cust-new-company", "Acme Pools")
    type_in(page, "#cust-new-first", "Ann")
    type_in(page, "#cust-new-last", "Lee")
    type_in(page, "#cust-new-phone", "386-555-0199")
    type_in(page, "#cust-new-email", "ann@acme.test")
    type_in(page, "#cust-new-city", "Edgewater")
    type_in(page, "#cust-new-zip", "32132")
    page.click("#cust-new-use")
    page.wait_for_selector("#bid-confirm-box")
    answer_yes(page, "bid")
    page.wait_for_function("() => document.body.innerText.includes('JOB-0001')")
    cust = fh.named("create_customer")[0]["updates"]
    assert cust["Company Name"] == "Acme Pools" and cust["First Name"] == "Ann" and cust["Last Name"] == "Lee"
    assert cust["Customer Type Comm/Res"] == "Commercial" and cust["ZIP"] == "32132"
    assert fh.named("create_quote")[0]["updates"]["Customer Name / Company"] == "Acme Pools"


def test_E2E_customer_picker_escape_closes(page, won_bid):
    bid_id, fh = won_bid
    _open_picker(page, bid_id)
    page.keyboard.press("Escape")
    assert page.locator("#cust-picker").count() == 0
    assert fh.named("create_quote") == []
