"""2026-11-14: a won quote becomes a job for an EXISTING AI-Prowler customer (picked in a popup) or a NEW one filled in
like the Jobs app's Add customer form (CP-..). Before, typing a name always made a new customer."""
import sqlite3

import pytest

from estimator.bids import service as bids
from estimator.context import personal_context
from estimator.errors import InvalidInput
from estimator.estimating import quick, service
from estimator.integrations import host
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
JANE = {"name": "Jane Smith", "email": "jane@example.com", "phone": "480-555-0101", "address": "42 Main St"}


def _approved(db):
    e = service.create_estimate(db, CTX, "Smith clean")
    e = quick.answer(db, CTX, e["id"], "house_cleaning", {"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, e["rev"], REG)
    return service.set_status(db, CTX, e["id"], e["rev"], "approved")

ROWS = [
    {"customer_id": "CUST-2026-616", "customer_type": "Residential", "company_name": "AI Prowler LLC",
     "first_name": "David", "last_name": "Vavro", "phone": "555-0100", "email": "d@example.com",
     "street_address": "1500 Shadow Pines Dr", "city": "New Smyrna Beach", "state": "FL", "zip": "32168", "status": "Active"},
    {"customer_id": "CUST-2026-12", "customer_type": "Commercial", "company_name": "Panera Bread Daytona",
     "first_name": "", "last_name": "", "phone": "", "email": "", "street_address": "1 Beach St", "city": "Daytona",
     "state": "FL", "zip": "", "status": "Active"},
]


@pytest.fixture
def picker_host(fake_host):
    def find(query="", limit=25, customer_id=None):
        if customer_id:
            return [r for r in ROWS if r["customer_id"] == customer_id]
        words = query.lower().split()
        return [r for r in ROWS if all(w in " ".join(str(v) for v in r.values()).lower() for w in words)][:limit]
    host.set_host(dict(fake_host.funcs(), find_customers=find))
    return fake_host


def _won(db, customer=JANE):
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=customer)
    bids.send(db, CTX, b["id"], confirm=True)
    return b


def test_find_customers_shapes_rows(db, picker_host):  # CP-01
    out = bids.find_customers(CTX, "prowler")
    assert out["count"] == 1
    c = out["customers"][0]
    assert c["customer_id"] == "CUST-2026-616" and c["name"] == "AI Prowler LLC" and c["address"] == "1500 Shadow Pines Dr"
    assert bids.find_customers(CTX, "")["count"] == 2


def test_existing_customer_makes_no_new_customer(db, picker_host):  # CP-02
    b = _won(db)
    with pytest.raises(bids.ConfirmationRequired) as q:
        bids.convert_to_job(db, CTX, b["id"], customer={"customer_id": "CUST-2026-616"})
    assert "a customer" not in str(q.value)                         # nothing new is made
    bids.convert_to_job(db, CTX, b["id"], confirm=True, customer={"customer_id": "CUST-2026-616"})
    assert picker_host.named("create_customer") == []
    quote = picker_host.named("create_quote")[0]["updates"]
    job = picker_host.named("create_job")[0]["updates"]
    # The picked customer's own name and address, not the quote's old Jane Smith ones.
    assert quote["CustomerID"] == "CUST-2026-616" and quote["Customer Name / Company"] == "AI Prowler LLC"
    assert job["CustomerID"] == "CUST-2026-616" and job["Street Address"] == "1500 Shadow Pines Dr"


def test_unknown_customer_id_is_refused(db, picker_host):  # CP-03
    b = _won(db)
    with pytest.raises(InvalidInput, match="no customer CUST-2026"):
        bids.convert_to_job(db, CTX, b["id"], confirm=True, customer={"customer_id": "CUST-2026"})
    assert picker_host.named("create_quote") == []


def test_new_customer_form_fields_reach_create_customer(db, picker_host):  # CP-04
    b = _won(db, customer=dict(JANE, customer_id="CUST-0042"))        # an old id on the quote is dropped
    new = {"customer_type": "commercial", "company": "Acme Pools", "first_name": "Ann", "last_name": "Lee",
           "phone": "555-0199", "email": "ann@acme.test", "address": "9 Palm Ave", "city": "Edgewater", "state": "FL",
           "zip": "32132"}
    bids.convert_to_job(db, CTX, b["id"], confirm=True, customer=new)
    cust = picker_host.named("create_customer")[0]["updates"]
    assert cust["First Name"] == "Ann" and cust["Last Name"] == "Lee" and cust["Company Name"] == "Acme Pools"
    assert cust["Customer Type Comm/Res"] == "Commercial" and cust["ZIP"] == "32132" and cust["City"] == "Edgewater"
    quote = picker_host.named("create_quote")[0]["updates"]
    assert quote["CustomerID"] == "CUST-0001" and quote["Customer Name / Company"] == "Acme Pools"


def test_customer_type_and_name_checks(db):  # CP-05
    assert bids.clean_customer({"first_name": "Ann", "last_name": "Lee"})["name"] == "Ann Lee"
    assert bids.clean_customer({"customer_type": "res"})["customer_type"] == "Residential"
    with pytest.raises(InvalidInput, match="Residential or Commercial"):
        bids.clean_customer({"customer_type": "alien"})


def test_real_lookup_reads_the_jobs_database(tmp_path, monkeypatch):  # CP-06
    path = tmp_path / "jobs.db"
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE customers (customer_id TEXT, customer_type TEXT, company_name TEXT, first_name TEXT,"
              " last_name TEXT, phone TEXT, email TEXT, street_address TEXT, city TEXT, state TEXT, zip TEXT, status TEXT,"
              " last_edited_at TEXT)")
    c.execute("INSERT INTO customers VALUES ('CUST-2026-616','Residential','AI Prowler LLC','David','Vavro','555','d@x.com',"
              "'1500 Shadow Pines Dr','NSB','FL','32168','Active','2026-11-14')")
    c.execute("INSERT INTO customers VALUES ('CUST-2026-1','Residential',NULL,'Jane','Smith','','','42 Main St','Mesa','AZ',"
              "'','Active','2026-01-01')")
    c.commit()
    c.close()
    host.set_host(None)
    monkeypatch.setattr(host, "_job_db_path", lambda: str(path))
    assert [r["customer_id"] for r in host.find_customers("")] == ["CUST-2026-616", "CUST-2026-1"]
    assert [r["customer_id"] for r in host.find_customers("shadow pines")] == ["CUST-2026-616"]
    assert host.find_customers(customer_id="CUST-2026-1")[0]["last_name"] == "Smith"
    assert host.find_customers(customer_id="CUST-2026") == []


def test_quote_for_a_customer_picked_by_id_only_gets_their_details(db, picker_host):  # CP-07 (2026-11-15, Jamie)
    # Seen on the server: the Director given customer={customer_id} made a quote with no name or address, and the
    # job's customer name was the ID itself.
    filled = bids.fill_from_prowler({"customer_id": "CUST-2026-616"})
    assert filled["name"] == "AI Prowler LLC" and filled["email"] == "d@example.com"
    assert filled["address"] == "1500 Shadow Pines Dr" and filled["customer_id"] == "CUST-2026-616"
    assert bids.fill_from_prowler({"customer_id": "CUST-2026-616", "email": "new@x.com"})["email"] == "new@x.com"
    assert bids.fill_from_prowler({"customer_id": "CUST-9999"}) == {"customer_id": "CUST-9999"}
    b = _won(db, customer={"customer_id": "CUST-2026-616", "email": "d@example.com"})   # a bid made with the ID only
    bids.convert_to_job(db, CTX, b["id"], confirm=True)
    job = picker_host.named("create_job")[0]["updates"]
    assert job["Customer Name / Company"] == "AI Prowler LLC" and job["Street Address"] == "1500 Shadow Pines Dr"
    assert picker_host.named("create_customer") == []


def test_director_fills_a_customer_picked_by_id(db, picker_host):  # CP-08 (2026-11-15, Jamie)
    from estimator.director import engine
    e = service.create_estimate(db, CTX, "Picked by id")
    r = engine.adopt(db, CTX, e["id"], registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], customer={"customer_id": "CUST-2026-616"}, registry=REG)
    cust = r["job"].get("customer") or engine.jobstore.load_job(db, CTX, r["job"]["id"])["customer"]
    assert cust["name"] == "AI Prowler LLC" and cust["email"] == "d@example.com"


def test_new_job_warns_about_missing_address_and_crew(db, picker_host):  # CP-09 (2026-11-15, Jamie)
    # Seen on the server: JOB-2063 had no address and was left off the Nov 18 route without a word, and Estimator
    # jobs have no crew, so in Server mode they're on nobody's route.
    b = _won(db, customer={"name": "No Address", "email": "n@x.com"})
    out = bids.convert_to_job(db, CTX, b["id"], confirm=True)
    assert any("no street address" in w for w in out["warnings"])
    assert not any("no crew" in w for w in out["warnings"])          # Personal mode: one route, no crews
    from dataclasses import replace
    server = replace(CTX, mode="server")
    assert any("no crew" in w for w in bids.job_warnings({"address": "1 Main St"}, server, "JOB-1"))
    assert bids.job_warnings({"address": "1 Main St"}, CTX, "JOB-1") == []
