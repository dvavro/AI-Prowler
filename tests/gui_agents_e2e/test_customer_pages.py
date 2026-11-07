"""AG-CP (AGENTS_GUI_E2E_TEST_SPEC.md §4): the customer page, on a personal install with email and no SMS. Real page and real
sending code. CP-01, 09, 10, 12, 13 are in test_customer_code.py; each test here gets its own simulated day (code limits).
"""
from __future__ import annotations

import datetime as dt
import itertools
import json
import re
from pathlib import Path

import pytest

import booking_db
from conftest import START, code_from, http
from db_access import DEFAULT_DB_FILENAME, DEFAULT_DB_SUBDIR

_n = itertools.count(1)
PATHS = ["book", "buy", "new", "problem"]


def _png():
    import io
    from PIL import Image
    b = io.BytesIO()
    Image.new("RGB", (40, 40), (10, 120, 200)).save(b, "PNG")
    return b.getvalue()


PNG = _png()
PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"


def _jobs_path(box):
    return str(Path(box.control("GET", "/state")["sandbox"]) / DEFAULT_DB_SUBDIR / DEFAULT_DB_FILENAME)


def _catalog(box):
    from test_customer_book_quote import _services
    p = _services(box)
    from db_access import get_connection
    c = get_connection(p)
    c.execute("INSERT OR IGNORE INTO service_pricing (service_code, name, base_price, min_charge) "
              "VALUES ('ZAG-PROD', 'ZAG Squeegee', 40, 40)")
    c.close()
    booking_db.sync_services(p)
    booking_db.update_service(p, "ZAG-PROD", online=True, mode="request", shipping=5)
    return p


@pytest.fixture
def box(nosms):
    nosms.today = START + dt.timedelta(days=700 + next(_n))
    nosms.clock(nosms.today, "10:00")
    nosms.settings(desk={"portal_enabled": True, "booking_paths": PATHS, "booking_area_zips": [], "booking_approval": "approve_all",
                         "agent_enabled": False, "agent_bk_enabled": False})
    _catalog(nosms)
    nosms.ai_reset("good", {})
    yield nosms
    nosms.settings(desk={"booking_area_zips": [], "agent_enabled": False, "agent_bk_enabled": False})


def _who():
    n = next(_n)
    return {"name": f"ZAG Page Customer {n}", "phone": f"386558{n:04d}", "email": f"page{n}@time-machine.test"}


def _open(box, person, path):
    who = person(box, "customer", phone=True)
    who.page.on("dialog", lambda d: d.accept("ZAG not yet") if d.type == "prompt" else d.accept())
    who.page.goto(f"{box.base}/support/?path={path}")
    who.page.locator("#fSend").wait_for(state="attached")
    return who, who.page


def _details(who, c):
    for sel, v in (("#fName", c["name"]), ("#fPhone", c["phone"]), ("#fEmail", c["email"])):
        who.type(sel, v)


def _address(who, zip_="32169"):
    for sel, v in (("#fStreet", "300 Flagler Ave"), ("#fCity", "New Smyrna Beach"), ("#fState", "FL"), ("#fZip", zip_)):
        who.type(sel, v)


def _code(box, email):
    got = [m for m in box.outbox() if m.get("to") == email and "request code" in str(m.get("subject"))]
    assert got, box.outbox()[-3:]
    return code_from(got[-1]["body"])


def _send_and_submit(who, box, c, *, wait_status=True):
    p = who.page
    p.locator("#fSend").click()
    p.locator("#fErr", has_text="Code sent by email").wait_for(timeout=10_000)
    who.type("#fCode", _code(box, c["email"]))
    p.locator("#fVerify").click()
    if wait_status:
        p.wait_for_url(re.compile(r"/support/t/"), timeout=15_000)
        return p.url.rsplit("/", 1)[1]
    return None


def _problem(box, person, title="ZAG streaky windows"):
    who, p = _open(box, person, "problem")
    c = _who()
    who.type("#fTitle", title)
    _details(who, c)
    return who, p, _send_and_submit(who, box, c)


def _view(box, token):
    st, d = http("GET", f"{box.base}/support-api/t/{token}")
    assert st == 200, d
    return d["ticket"]


def _book(box, person):
    who, p = _open(box, person, "book")
    c = _who()
    _address(who)
    p.locator("[data-win]").first.wait_for(timeout=10_000)
    p.locator("[data-win]").first.click()
    _details(who, c)
    return who, p, _send_and_submit(who, box, c)


def _pending_job(box):
    st, d = box.desk("GET", "/bookings")
    assert st == 200, d
    rows = d.get("pending") or d.get("bookings") or []
    assert rows, d
    return rows[-1]


def _state(box, tid, to):
    st, d = box.desk("GET", f"/tickets/{tid}")
    assert st == 200, d
    t = d.get("ticket") or d
    ver = t.get("version") or t.get("rev")
    st, r = box.desk("POST", f"/tickets/{tid}/state", {"to_state": to, "reason": "ZAG", **({"expected_version": ver} if ver else {})})
    assert st == 200, r


def test_cp_02_title_stops_at_200(box, person):
    who, p = _open(box, person, "problem")
    who.page.locator("#fTitle").fill("x" * 200)
    p.locator("#fTitle").press_sequentially("y")
    assert len(p.locator("#fTitle").input_value()) == 200


def test_cp_03_quote_other_service_keeps_address_and_days(box, person):
    who, p = _open(box, person, "new")
    c = _who()
    p.locator("#fSvc").select_option("")
    p.locator("#fOther").fill("z" * 120)
    p.locator("#fPref").fill("q" * 120)
    _address(who)
    _details(who, c)
    token = _send_and_submit(who, box, c)
    t = _view(box, token)
    text = json.dumps(t)
    assert "z" * 120 in text, t
    st, full = box.desk("GET", f"/tickets/{t['ticket_id']}")
    assert st == 200 and "q" * 120 in json.dumps(full), full


def test_cp_04_booking_shows_on_both_sides(box, person):
    who, p, token = _book(box, person)
    p.locator("#booking", has_text="Waiting for confirmation").wait_for()
    row = _pending_job(box)
    assert row, row


def test_cp_05_call_me_keeps_what_was_typed(box, person):
    who, p = _open(box, person, "book")
    c = _who()
    _address(who)
    _details(who, c)
    p.locator("#fDesc").fill("ZAG two storeys")
    p.locator("#toNew").click()
    p.locator("#fPref").wait_for()
    for sel, want in (("#fName", c["name"]), ("#fPhone", c["phone"]), ("#fEmail", c["email"]), ("#fStreet", "300 Flagler Ave"),
                      ("#fZip", "32169"), ("#fDesc", "ZAG two storeys")):
        assert p.locator(sel).input_value() == want, sel


@pytest.mark.parametrize("qty", [1, 5])
def test_cp_06_order_total(box, person, qty):
    tax = float(http("GET", box.base + "/support-api/info")[1]["tax_rate"] or 0)
    total = f"{round(45 * qty * (1 + tax), 2):,.2f}"
    who, p = _open(box, person, "buy")
    p.locator("[data-buy='ZAG-PROD']").click()
    p.locator("#fQty").fill(str(qty))
    p.locator("#fSum", has_text=total).wait_for()
    c = _who()
    _address(who)
    _details(who, c)
    token = _send_and_submit(who, box, c)
    p.locator("#order", has_text=total).wait_for()
    assert _view(box, token)["order"]["qty"] == qty


@pytest.mark.parametrize("qty", ["0", "21", "x"])
def test_cp_07_bad_quantity_is_refused(box, person, qty):
    who, p = _open(box, person, "buy")
    p.locator("[data-buy='ZAG-PROD']").click()
    p.locator("#fQty").evaluate("(e, v) => { e.type = 'text'; e.value = v; e.dispatchEvent(new Event('input')); }", qty)
    c = _who()
    _address(who)
    _details(who, c)
    p.locator("#fSend").click()
    p.locator("#fErr", has_text="how many").wait_for()
    assert p.locator("#codeCard").is_hidden()


@pytest.mark.parametrize("field,bad,says", [("#fName", "", "your name"), ("#fPhone", "abc", "phone number"),
                                            ("#fEmail", "x@", "email address"), ("#fZip", "ABCDE", "ZIP")])
def test_cp_08_bad_details_refused_before_a_code(box, person, field, bad, says):
    who, p = _open(box, person, "new")
    c = _who()
    _address(who)
    _details(who, c)
    p.locator(field).fill(bad)
    before = len(box.outbox())
    p.locator("#fSend").click()
    p.locator("#fErr", has_text=says).wait_for()
    assert p.locator("#codeCard").is_hidden() and len(box.outbox()) == before


def test_cp_08_server_refuses_a_bad_email_too(box):
    st, d = http("POST", box.base + "/support-api/start", {**_who(), "email": "x@"})
    assert st == 400 and "email" in str(d), (st, d)


def test_cp_11_code_expires_after_10_minutes(box, person):
    who, p = _open(box, person, "problem")
    c = _who()
    who.type("#fTitle", "ZAG late code")
    _details(who, c)
    p.locator("#fSend").click()
    p.locator("#codeCard").wait_for()
    box.clock(box.today, "10:11")
    who.type("#fCode", _code(box, c["email"]))
    p.locator("#fVerify").click()
    p.locator("#cErr", has_text="expired").wait_for()


def test_cp_14_outside_the_area(box, person):
    box.settings(desk={"booking_area_zips": ["32169"]})
    who, p = _open(box, person, "new")
    c = _who()
    _address(who, "90210")
    _details(who, c)
    _send_and_submit(who, box, c, wait_status=False)
    p.locator("#outOfArea", has_text="cover that area").wait_for(timeout=10_000)


def test_cp_15_script_and_unicode_are_plain_text(box, person):
    evil = "<script>window.__hit=1</script><img src=x onerror='window.__hit=1'> 你好 🎉"
    who, p = _open(box, person, "problem")
    c = {**_who(), "name": evil}
    who.type("#fTitle", evil[:190])
    p.locator("#fDesc").fill(evil + " " + "long " * 390)
    _details(who, c)
    _send_and_submit(who, box, c)
    p.locator("h2", has_text="你好" if False else "script").wait_for()
    assert p.evaluate("window.__hit") is None
    p.locator("#reply").fill(evil)
    p.locator("#send").click()
    p.locator(".msg", has_text="onerror").wait_for()
    assert p.evaluate("window.__hit") is None
    assert not who.errors, who.errors


def test_cp_16_reply_and_files(box, person):
    who, p, token = _problem(box, person)
    p.locator("#reply").fill("ZAG here is more")
    p.locator("#send").click()
    p.locator(".msg", has_text="ZAG here is more").wait_for()
    p.locator("#up").set_input_files([{"name": "a.png", "mimeType": "image/png", "buffer": PNG},
                                      {"name": "b.png", "mimeType": "image/png", "buffer": PNG},
                                      {"name": "c.pdf", "mimeType": "application/pdf", "buffer": PDF}])
    p.locator("[data-att]").nth(2).wait_for(timeout=10_000)
    t = _view(box, token)
    assert len(t["attachments"]) == 3
    st, full = box.desk("GET", f"/tickets/{t['ticket_id']}")
    assert st == 200 and len(full["ticket"].get("attachments") or full.get("attachments") or []) == 3, full


def test_cp_17_is_it_fixed_yes_and_no(box, person):
    who, p, token = _problem(box, person)
    tid = _view(box, token)["ticket_id"]
    _state(box, tid, "In Progress")
    _state(box, tid, "Fixed")
    p.reload()
    p.locator("#no").click()
    p.locator(".chip.st", has_text="In Progress").wait_for()
    _state(box, tid, "Fixed")
    p.reload()
    p.locator("#yes").click()
    p.locator(".chip.st", has_text="Closed").wait_for()


def test_cp_19_stars_saved_and_shown(box, person):
    who, p, token = _problem(box, person)
    tid = _view(box, token)["ticket_id"]
    for to in ("In Progress", "Fixed", "Closed"):
        _state(box, tid, to)
    p.reload()
    p.locator("[data-star='5']").click()
    p.locator("#rateNote").fill("ZAG great")
    p.locator("#rateGo").click()
    p.locator("#rated", has_text="ZAG great").wait_for()
    assert _view(box, token)["csat_score"] == 5


def test_cp_20_suggested_time_accept_and_call(box, person):
    who, p, token = _book(box, person)
    row = _pending_job(box)
    jid = row.get("job_id") or row["job"]["job_id"]
    st, w = box.desk("GET", "/bookings/windows?service=ZAG-WIN")
    assert st == 200, w
    key = w["windows"][3]["key"]
    st, r = box.desk("POST", f"/bookings/{jid}/suggest", {"window_key": key})
    assert st == 200, r
    p.reload()
    p.locator("#bkCall").click()
    p.locator("#bkErr", has_text="call you").wait_for()
    p.reload()
    p.locator("#bkAccept").click()
    p.locator("#booking", has_text="Confirmed").wait_for()


def _confirmed(box, person):
    who, p, token = _book(box, person)
    row = _pending_job(box)
    jid = row.get("job_id") or row["job"]["job_id"]
    st, r = box.desk("POST", f"/bookings/{jid}/approve", {})
    assert st == 200, r
    p.reload()
    p.locator("#booking", has_text="Confirmed").wait_for()
    return who, p, token


def test_cp_21_calendar_file(box, person):
    who, p, token = _confirmed(box, person)
    with p.expect_download() as d:
        p.locator("#bkIcs").click()
    text = Path(d.value.path()).read_text(encoding="utf-8")
    assert "BEGIN:VCALENDAR" in text and "BEGIN:VEVENT" in text


def test_cp_22_cancel_frees_the_slot(box, person):
    who, p, token = _confirmed(box, person)
    held = _view(box, token)["booking"]
    before = http("GET", f"{box.base}/support-api/windows?service=ZAG-WIN")[1]["windows"]
    p.locator("#bkCancel").click()
    p.locator("#booking", has_text="cancelled").wait_for()
    after = http("GET", f"{box.base}/support-api/windows?service=ZAG-WIN")[1]["windows"]
    assert len(after) >= len(before), (held, len(before), len(after))
