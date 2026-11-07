"""Sprint 4: bids — generate, preview, send, status, convert to an AI-Prowler job (S4-B..)."""
import pytest

from estimator.bids import render
from estimator.bids import service as bids
from estimator.context import RequestContext, personal_context
from estimator.errors import InvalidInput, NotEditable, NotFound, PermissionDenied
from estimator.estimating import quick, service, setup
from estimator.integrations import host
from estimator.modules.registry import ModuleRegistry
from estimator.pricing.price_book import set_price

CTX = personal_context()
REG = ModuleRegistry().load()
JANE = {"name": "Jane Smith", "email": "jane@example.com", "phone": "480-555-0101", "address": "42 Main St"}


def _approved(db, answers=None, module="house_cleaning", markups=None):
    if markups:
        service.save_markups(db, CTX, **markups)
    e = service.create_estimate(db, CTX, "Smith clean")
    e = quick.answer(db, CTX, e["id"], module, answers or {"bedrooms": 3, "bathrooms": 2, "sqft": 1800},
                     e["rev"], REG)
    return service.set_status(db, CTX, e["id"], e["rev"], "approved")


def test_bid_needs_approved_estimate(db):  # S4-B01
    e = service.create_estimate(db, CTX, "x")
    with pytest.raises(NotEditable, match="approve"):
        bids.generate(db, CTX, e["id"])
    with pytest.raises(NotFound):
        bids.generate(db, CTX, 999)


def test_generate_freezes_prices_and_numbers_versions(db):  # S4-B02
    e = _approved(db)
    b1 = bids.generate(db, CTX, e["id"], customer=JANE)
    assert b1["number"] == f"Q-{e['id']:04d}-1" and b1["total_cents"] == 26750 and b1["status"] == "draft"
    assert b1["html_path"].endswith(".html") and b1["pdf_path"] is None and b1["warnings"]   # no browser in tests
    set_price(db, "default", "hc_labor_hr", description="new", kind="other", unit="hr", cost_cents=9900)
    assert bids.preview(db, CTX, b1["id"])["total_cents"] == 26750          # frozen
    b2 = bids.generate(db, CTX, e["id"])
    assert b2["version"] == 2 and b2["number"].endswith("-2")


def test_html_hides_costs_and_shows_tax_separately(db):  # S4-B03
    e = _approved(db, {"hours": 2, "materials_dollars": "100"}, "generic_service",
                  markups={"overhead_pct": "0.10", "profit_pct": "0.20", "tax_pct": "0.08"})
    b = bids.generate(db, CTX, e["id"], customer=JANE)
    html = open(b["html_path"], encoding="utf-8").read()
    prev = bids.preview(db, CTX, b["id"])
    t = prev["totals"]
    assert t["lines_cents"] + t["tax_cents"] + t["adjustment_cents"] == t["total_cents"] == b["total_cents"]
    assert t["tax_cents"] == 800                                  # 8% on $100 materials cost
    assert "Sales tax" in html and "Jane Smith" in html and "overhead" not in html.lower()
    assert "$60.00" not in html                                   # the raw labor cost never shows
    assert "TOTAL" in prev["text"]


def test_template_terms_and_valid_days(db):  # S4-B04
    setup.setup_step(db, CTX, "bid_template", {"terms": "Net 15. Valid until {valid_until}.", "valid_days": 10})
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"])
    html = open(b["html_path"], encoding="utf-8").read()
    assert "Net 15. Valid until " + b["valid_until"] in html
    with pytest.raises(InvalidInput):
        bids.generate(db, CTX, e["id"], valid_days=999)


def test_send_needs_confirm_and_an_address(db, fake_host):  # S4-B05
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"])
    with pytest.raises(InvalidInput, match="email"):
        bids.send(db, CTX, b["id"])
    with pytest.raises(bids.ConfirmationRequired) as exc:
        bids.send(db, CTX, b["id"], to="jane@example.com")
    assert exc.value.code == "needs_confirmation" and fake_host.named("send_email") == []


def test_send_emails_and_marks_sent(db, fake_host):  # S4-B06
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=JANE)
    out = bids.send(db, CTX, b["id"], confirm=True, message="Thanks for calling!")
    mail = fake_host.named("send_email")[0]
    assert mail["to"] == "jane@example.com" and "Q-" in mail["subject"] and "$267.50" in mail["subject"]
    assert "<html" in mail["body_html"] and "Thanks for calling!" in mail["body"]
    assert out["status"] == "sent" and out["sent_to"] == "jane@example.com"
    assert service.get_estimate(db, CTX, e["id"])["status"] == "sent"


def test_send_retries_without_attachment(db, fake_host, tmp_path):  # S4-B07
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=JANE)
    pdf = tmp_path / "q.pdf"
    pdf.write_bytes(b"%PDF-1.4 test")
    db.execute("UPDATE bids SET pdf_path = ? WHERE id = ?", (str(pdf), b["id"]))
    calls = {"n": 0}
    real = fake_host.funcs()["send_email"]

    def picky(**kw):
        calls["n"] += 1
        if "attachment_path" in kw:
            return "❌ attachment is not in a tracked read-allowlisted directory"
        return real(**kw)
    host.set_host(dict(fake_host.funcs(), send_email=picky))
    out = bids.send(db, CTX, b["id"], confirm=True)
    assert calls["n"] == 2 and out["status"] == "sent" and "without the PDF" in out["warnings"][0]


def test_send_failure_keeps_draft(db, fake_host):  # S4-B08
    fake_host.fail["send_email"] = "❌ Email is not configured"
    host.set_host(fake_host.funcs())
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=JANE)
    with pytest.raises(host.HostError, match="not configured"):
        bids.send(db, CTX, b["id"], confirm=True)
    assert bids.preview(db, CTX, b["id"])["status"] == "draft"


def test_status_follows_to_estimate(db, fake_host):  # S4-B09
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=JANE)
    bids.send(db, CTX, b["id"], confirm=True)
    bids.set_status(db, CTX, b["id"], "viewed")
    bids.set_status(db, CTX, b["id"], "lost")
    assert service.get_estimate(db, CTX, e["id"])["status"] == "lost"
    with pytest.raises(NotEditable):
        bids.set_status(db, CTX, b["id"], "won")
    with pytest.raises(InvalidInput):
        bids.set_status(db, CTX, b["id"], "sent")


def test_convert_creates_customer_quote_and_job(db, fake_host):  # S4-B10
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=JANE)
    bids.send(db, CTX, b["id"], confirm=True)
    with pytest.raises(bids.ConfirmationRequired):
        bids.convert_to_job(db, CTX, b["id"])
    out = bids.convert_to_job(db, CTX, b["id"], confirm=True, service_date="2026-11-20")
    cust = fake_host.named("create_customer")[0]["updates"]
    quote = fake_host.named("create_quote")[0]["updates"]
    job = fake_host.named("create_job")[0]["updates"]
    assert cust["First Name"] == "Jane" and cust["Last Name"] == "Smith" and cust["Email"] == "jane@example.com"
    assert quote["CustomerID"] == "CUST-0001" and quote["QUOTE TOTAL ($)"] == "267.50"
    assert quote["Status (Open/Approved/Declined)"] == "Approved" and quote["Service Type"] == "House Cleaning"
    assert job["CustomerID"] == "CUST-0001" and job["Service Date"] == "2026-11-20" and job["Job Status"] == "Scheduled"
    assert job["Quote Amount ($)"] == "267.50" and "QTE-0001" in job["Service Details / Notes"]
    assert out["status"] == "won" and out["quote_id"] == "QTE-0001" and out["job_id"] == "JOB-0001"
    est = service.get_estimate(db, CTX, e["id"])
    assert est["status"] == "won" and est["job_id"] == "JOB-0001" and est["customer_id"] == "CUST-0001"
    again = bids.convert_to_job(db, CTX, b["id"], confirm=True)
    assert again["already_converted"] and len(fake_host.named("create_job")) == 1


def test_convert_existing_customer_skips_create(db, fake_host):  # S4-B11
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=dict(JANE, customer_id="CUST-0042"))
    bids.send(db, CTX, b["id"], confirm=True)
    bids.convert_to_job(db, CTX, b["id"], confirm=True)
    assert fake_host.named("create_customer") == []
    assert fake_host.named("create_quote")[0]["updates"]["CustomerID"] == "CUST-0042"
    assert "Service Date" not in fake_host.named("create_job")[0]["updates"]


def test_convert_needs_a_customer_and_a_live_bid(db, fake_host):  # S4-B12
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"])
    with pytest.raises(NotEditable):
        bids.convert_to_job(db, CTX, b["id"], confirm=True)          # still a draft
    bids.send(db, CTX, b["id"], to="x@y.com", confirm=True)
    with pytest.raises(InvalidInput, match="customer"):
        bids.convert_to_job(db, CTX, b["id"], confirm=True)
    with pytest.raises(InvalidInput, match="service_date"):
        bids.convert_to_job(db, CTX, b["id"], confirm=True, customer={"name": "Al"}, service_date="next week")


def test_host_unavailable_is_clear(db):  # S4-B13
    host.set_host(None)
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=JANE)
    with pytest.raises(host.HostUnavailable):
        bids.send(db, CTX, b["id"], confirm=True)


def test_customer_validation_and_roles(db):  # S4-B14
    e = _approved(db)
    with pytest.raises(InvalidInput):
        bids.generate(db, CTX, e["id"], customer={"name": "x", "email": "not-an-email"})
    with pytest.raises(InvalidInput):
        bids.generate(db, CTX, e["id"], customer={"shoe_size": 9})
    with pytest.raises(PermissionDenied):
        bids.generate(db, RequestContext(role="reviewer", user_id="r", mode="server"), e["id"])


def test_dollars_and_list(db):  # S4-B15
    assert bids.dollars(26750) == "267.50" and bids.dollars(5) == "0.05" and bids.dollars(-150) == "-1.50"
    e = _approved(db)
    bids.generate(db, CTX, e["id"])
    assert bids.list_bids(db, CTX)["count"] == 1 and bids.list_bids(db, CTX, status="sent")["count"] == 0
    other = RequestContext(company_id="acme", user_id="z", mode="server")
    assert bids.list_bids(db, other)["count"] == 0


def test_host_id_extraction():  # S4-B16
    assert host.extract_id("✅ Customer added\nNEW_CUST_ID=CUST-0012\n", "CUST") == "CUST-0012"
    assert host.extract_id("✅ Created job JOB-0099 for Jane", "JOB") == "JOB-0099"
    assert host.extract_id("✅ done", "QTE") is None


def test_pdf_with_real_browser(db, monkeypatch):  # S4-B17
    monkeypatch.delenv("ESTIMATOR_PDF_BROWSER", raising=False)
    if render.find_browser() is None:
        pytest.skip("no Edge/Chrome/Chromium on this machine")
    e = _approved(db)
    b = bids.generate(db, CTX, e["id"], customer=JANE)
    assert b["pdf_path"] and open(b["pdf_path"], "rb").read(4) == b"%PDF"
