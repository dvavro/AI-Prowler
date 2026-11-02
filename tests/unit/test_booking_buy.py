"""'Buy a product' on the customer page (2026-11-02).

David: "I think we are missing Allow a product to be purchased ... add the Online Payment Link for
each product ... shipping and handling needs to be added in."
An order = a Requested job (to ship) + an Unpaid invoice (items + S&H per item + tax) + a ticket whose
page has Pay now — a fresh Stripe / Square checkout link for what's owed. Never touches real
payment services: checkout_fn is a fake here.
Run: run_tests.bat tests\\unit\\test_booking_buy.py
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import booking_db  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_settings as dgs  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

PHONE, E164, EMAIL = "(386) 555-0142", "+13865550142", "lopez@example.com"
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    desk_db.set_setting(tickets, "portal_enabled", True, edition=r.SOLO)
    desk_db.set_setting(tickets, "booking_paths", ["buy", "new", "problem"], edition=r.SOLO)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.executemany("INSERT INTO service_pricing (service_code, category, name, base_price, min_charge) "
                     "VALUES (?, ?, ?, ?, ?)", [("WIN-EXT", "Windows", "Exterior windows", 150.0, 95.0),
                                                ("SSD", "Hardware", "Mini Server .5TB SSD", 250.0, None),
                                                ("CABLE", "Hardware", "Cable kit", None, None)])
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('Tax Rate', '0.07')")
    conn.close()
    booking_db.sync_services(jobs)
    booking_db.update_service(jobs, "WIN-EXT", online=True)
    booking_db.update_service(jobs, "SSD", online=True, mode="request", shipping="$15")
    booking_db.update_service(jobs, "CABLE", online=True, mode="request")       # no price yet
    sent, made = [], []
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, text)) or True
    p.channels_fn = lambda: {"email": True, "sms": True}
    p.jobs_db_fn = lambda: jobs
    p.checkout_ready_fn = lambda: True

    def fake_checkout(amount, description, ref, return_url=""):
        made.append((amount, description, ref, return_url))
        return f"https://pay.example.test/{ref}?amount={amount:.2f}"
    p.checkout_fn = fake_checkout
    yield tickets, jobs, sent, made
    p.send_fn = p.channels_fn = p.jobs_db_fn = p.checkout_fn = p.checkout_ready_fn = None


def api(db, method, path, body=None):
    st, ct, out = p.route(method, "/support-api" + path, query={}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", ip="1.2.3.4", db_path=db, edition=r.SOLO,
                          base_url="https://x.example", business="Blue Wave")
    return st, json.loads(out)


def code_for(sent, to):
    return re.search(r"\b(\d{6})\b", [t for _c, d, t in sent if d == to and "code is" in t][-1]).group(1)


def start(env):
    tickets, _j, sent, _m = env
    st, d = api(tickets, "POST", "/start", {"name": "Maria Lopez", "phone": PHONE, "email": EMAIL})
    assert st == 200, d
    return d["contact_id"], code_for(sent, E164)


def order(env, **extra):
    cid, code = start(env)
    body = {"contact_id": cid, "code": code, "path": "buy", "service_code": "SSD", "qty": 2, "address": ADDR}
    body.update(extra)
    return api(env[0], "POST", "/verify", body)


def test_buy_is_a_page_choice_in_page_order():
    assert desk_db.BOOKING_PATHS == ("book", "buy", "new", "problem")
    assert set(dgs.PATH_LABELS) == set(desk_db.BOOKING_PATHS) == set(dgs.PATH_HELP)


def test_the_shop_lists_online_products_with_shipping_and_whether_they_can_be_bought(env):
    st, d = api(env[0], "GET", "/info")
    assert d["paths"] == ["buy", "new", "problem"] and d["pay_online"] is True and d["tax_rate"] == 0.07
    prods = {p["code"]: p for p in d["products"]}
    assert set(prods) == {"SSD", "CABLE"}                                          # products only, no services
    assert prods["SSD"] == {"code": "SSD", "name": "Mini Server .5TB SSD", "description": "", "unit_price": 250.0,
                            "shipping": 15.0, "buyable": True, "specs": "", "photos": []}
    assert prods["CABLE"]["buyable"] is False                                       # no price: "Ask about it"


def _png():
    import io
    from PIL import Image
    b = io.BytesIO()
    Image.new("RGB", (1600, 900), (20, 120, 200)).save(b, "PNG")
    return b.getvalue()


def test_products_have_specs_and_up_to_four_photos_shown_on_the_page(env):
    """David 2026-11-02: "we need to be able to show the products (pictures and specs)"."""
    import desk_product_media as media
    tickets, jobs, _s, _m = env
    ok, msg = dgs.save_details(jobs, "SSD", "Small and quiet", "Storage: 0.5 TB SSD\n\n  Warranty: 1 year  \n")
    assert ok, msg
    assert dgs.product_details(jobs, tickets, "SSD")["specs"] == "Storage: 0.5 TB SSD\nWarranty: 1 year"
    assert not dgs.save_details(jobs, "SSD", "", "x" * 2001)[0]                    # too long
    for _ in range(4):
        assert media.add_photo(tickets, "SSD", _png())
    with pytest.raises(desk_db.DeskError, match="up to 4 photos"):
        media.add_photo(tickets, "SSD", _png())
    with pytest.raises(desk_db.DeskError, match="isn't a picture"):
        media.add_photo(tickets, "CABLE", b"not a picture")
    from PIL import Image
    import io
    img = Image.open(io.BytesIO(media.photo_bytes(tickets, "SSD", 1)))
    assert img.format == "JPEG" and max(img.size) == media.SIDE                    # resized, no EXIF kept
    media.remove_photo(tickets, "SSD", 2)
    assert media.photos(tickets, "SSD") == [1, 2, 3]                               # renumbered
    st, d = api(tickets, "GET", "/info")
    p = next(x for x in d["products"] if x["code"] == "SSD")
    assert p["description"] == "Small and quiet" and p["specs"].startswith("Storage:") and len(p["photos"]) == 3
    st, ct, body = p_route(tickets, p["photos"][0].split("?")[0])
    assert st == 200 and ct == b"image/jpeg" and body[:2] == b"\xff\xd8"
    # a product that isn't online never shows its photos
    booking_db.update_service(jobs, "SSD", online=False)
    st, _ct, _b = p_route(tickets, p["photos"][0].split("?")[0])
    assert st == 404


def p_route(db, path):
    return p.route("GET", path, query={}, body=b"", content_type="", ip="1.2.3.4", db_path=db,
                   edition=r.SOLO, base_url="https://x.example", business="Blue Wave")


def test_the_total_adds_shipping_per_item_and_tax(env):
    q = booking_db.order_quote(env[1], "SSD", 2)
    assert (q["items"], q["shipping"], q["subtotal"], q["tax"], q["total"]) == (500.0, 30.0, 530.0, 37.1, 567.1)


@pytest.mark.parametrize("code,qty,msg", [("SSD", 0, "1 to 20"), ("SSD", 21, "1 to 20"), ("SSD", "x", "how many"),
                                          ("CABLE", 1, "no price yet"), ("WIN-EXT", 1, "isn't sold online")])
def test_what_cant_be_bought_is_refused_before_the_code_is_used(env, code, qty, msg):
    cid, c = start(env)
    st, d = api(env[0], "POST", "/verify", {"contact_id": cid, "code": c, "path": "buy",
                                            "service_code": code, "qty": qty, "address": ADDR})
    assert st == 400 and msg in d["message"]
    st, d = api(env[0], "POST", "/verify", {"contact_id": cid, "code": c, "path": "buy",   # same code still works
                                            "service_code": "SSD", "qty": 1, "address": ADDR})
    assert st == 201, d


def test_an_order_needs_a_shipping_address(env):
    st, d = order(env, address={"street": "", "city": "", "state": "", "zip": ""})
    assert st == 400 and "shipping address" in d["message"]


def test_an_order_makes_a_job_an_unpaid_invoice_and_a_ticket(env):
    tickets, jobs, sent, _m = env
    st, d = order(env, description="Leave it at the side door")
    assert st == 201 and d["job_id"] and d["order"]["total"] == 567.1
    conn = get_connection(jobs)
    job = dict(conn.execute("SELECT * FROM jobs WHERE job_id = ?", (d["job_id"],)).fetchone())
    inv = dict(conn.execute("SELECT * FROM invoices WHERE invoice_id = ?", (job["invoice_id"],)).fetchone())
    req = dict(conn.execute("SELECT * FROM booking_requests WHERE job_id = ?", (d["job_id"],)).fetchone())
    conn.close()
    assert job["job_status"] == "Requested" and not job["service_date"]          # never routed
    assert job["service_type"] == "Order: Mini Server .5TB SSD" and "Ship to: 12 Ocean Ave" in job["service_details"]
    assert (inv["subtotal"], inv["tax"], inv["total_due"], inv["payment_status"]) == (530.0, 37.1, 567.1, "Unpaid")
    assert req["path"] == "buy" and req["status"] == "ordered" and req["ticket_id"] == d["ticket_id"]
    t = desk_db.get_ticket(tickets, d["ticket_id"], actor={"id": "owner", "role": "owner"}, edition=r.SOLO)
    assert t["title"] == "Order: Mini Server .5TB SSD × 2 + shipping & handling" and t["job_id"] == d["job_id"]
    assert "Shipping & handling: $30.00" in t["description"] and "Total: $567.10" in t["description"]
    assert "total $567.10" in sent[-1][2] and "Pay and track it here" in sent[-1][2]


def test_pay_now_makes_a_fresh_link_for_what_is_owed_until_paid(env):
    tickets, jobs, _s, made = env
    st, d = order(env)
    st, v = api(tickets, "GET", f"/t/{d['token']}")
    o = v["ticket"]["order"]
    assert o["can_pay"] and o["pay_online"] and o["due"] == 567.1 and o["ship_to"].startswith("12 Ocean Ave")
    st, pay = api(tickets, "POST", f"/t/{d['token']}/order/pay")
    assert st == 200 and pay["url"].endswith("?amount=567.10")
    assert made[-1][3] == f"https://x.example/support/t/{d['token']}"            # back to their page after paying
    conn = get_connection(jobs)
    conn.execute("UPDATE invoices SET amount_paid = total_due, payment_status = 'Paid'")
    conn.close()
    st, v = api(tickets, "GET", f"/t/{d['token']}")
    assert v["ticket"]["order"]["paid"] is True and v["ticket"]["order"]["can_pay"] is False
    st, pay = api(tickets, "POST", f"/t/{d['token']}/order/pay")
    assert st == 400 and "already paid" in pay["message"]


def test_without_payment_keys_the_order_is_taken_and_the_invoice_sent(env):
    tickets, _j, sent, _m = env
    p.checkout_ready_fn = lambda: False
    st, d = api(tickets, "GET", "/info")
    assert d["pay_online"] is False
    st, d = order(env)
    assert st == 201 and "We'll send you the invoice" in sent[-1][2]
    st, pay = api(tickets, "POST", f"/t/{d['token']}/order/pay")
    assert st == 400 and "send you the invoice" in pay["message"]


def test_a_failed_checkout_says_try_again(env):
    st, d = order(env)
    p.checkout_fn = lambda *a, **k: None
    st, pay = api(env[0], "POST", f"/t/{d['token']}/order/pay")
    assert st == 400 and "try again" in pay["message"]


def test_shipping_is_set_per_product_only(env):
    jobs = env[1]
    assert dgs.set_shipping(jobs, "SSD", "12.5") == (True, "Saved — shipping & handling $12.50 per item.")
    assert dgs.set_shipping(jobs, "SSD", "") == (True, "Saved — free shipping.")
    ok, msg = dgs.set_shipping(jobs, "SSD", "-3")
    assert not ok and "$0 to" in msg
    ok, msg = dgs.set_shipping(jobs, "WIN-EXT", "5")
    assert not ok and "Only products are shipped" in msg
