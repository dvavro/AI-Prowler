"""Coder 2 Sprint 13 E2E GUI tests (Playwright, human mode): reviews on a phone or tablet — approve in a row,
swipe guards, phone relabel vs desktop, phone measurement approval, tablet layout, field staff, server-mode thumbnails.

    run_tests_estimator.bat browser -k E2E_S13 [--human]

Builds on the existing Sprint 13 browser tests (test_browser_sprint13.py: B01..B06) and extends the assertions to the
full M-check wording. See tests/estimator/E2E_GUI_TEST_PLAN.md. M1 stays MANUAL (real device + Remote Access).
"""
import json

import pytest

from browser_helpers import answer_yes
from e2e_helpers import CTX, dismiss_tour, sign_in_as
from estimator.drawing_model import engine, store
from estimator.estimating import quick, service
from estimator.takeoff import measurements as ms
from pdfmaker import make_pdf, title_block
from test_plan_engine_sprint10 import legend, plan, shape

CTX_ = CTX
QUARTER = 'SCALE: 1/4" = 1\'-0"'


def _square(x, y, size):
    return [(x, y, x + size, y), (x + size, y, x + size, y + size), (x + size, y + size, x, y + size), (x, y + size, x, y)]


@pytest.fixture
def job(db, tmp_path):
    """Jones power: 3 receptacles and 2 symbols the legend doesn't name. Smith house: a 12 x 12 ft KITCHEN measured
    from the room (to approve) and a typed floor area (no place on the plan). Same seed as test_browser_sprint13.py."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("flag", 12, 8) + \
        shape("flag", 14, 8, 30)
    jones = service.create_estimate(db, CTX, "Jones power")
    ps = store.upload(db, CTX, jones["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    texts = title_block("A-101", "FIRST FLOOR PLAN") + [(4, 21, 14, "FLOOR PLAN"), (4, 21.35, 9, QUARTER),
                                                        (6, 6.4, 10, "KITCHEN")]
    smith = service.create_estimate(db, CTX, "Smith house")
    ps2 = store.upload(db, CTX, smith["id"], str(make_pdf(tmp_path / "smith.pdf", [{"w": 36, "h": 24, "texts": texts,
                                                                                     "lines": _square(5, 5, 3)}])),
                       confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps2, confirm=True)
    room = db.execute("SELECT o.id FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id WHERE s.plan_set_id = ?"
                      " AND o.kind = 'room'", (ps2,)).fetchone()[0]
    m = ms.propose(db, CTX, smith["id"], "flooring", [room], feeds="area_sqft", room="KITCHEN", confirm=True)
    ms.manual(db, CTX, smith["id"], "flooring", feeds="area_sqft", qty="300", unit="sqft", confirm=True)
    # M5: the trade must be answered before it can be re-priced from measurements (flooring requires material;
    # the area then comes from the approved measurement). Price it at the typed 300 sqft for now.
    rev = service.get_estimate(db, CTX, smith["id"])["rev"]
    quick.answer(db, CTX, smith["id"], "flooring", {"area_sqft": 300, "material": "lvp"}, rev)
    db.commit()
    return {"jones": jones["id"], "jones_ps": ps, "smith": smith["id"], "room_m": m["proposed"][0]["id"]}


@pytest.fixture
def many_symbols(db, tmp_path):
    """12 symbols on one sheet (8 receptacles, 4 special devices) so ten can be approved in a row."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = ll
    for i in range(8):
        lines += shape("recept", 5 + 2 * i, 5)
    for i in range(4):
        lines += shape("flag", 5 + 2 * i, 8)
    est = service.create_estimate(db, CTX, "Jones power")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "power12.pdf", [plan(lt, lines)])),
                      confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


@pytest.fixture
def flags_only(db, tmp_path):
    """5 identical symbols the legend doesn't name, so relabelling one with 'every identical match' changes all 5."""
    lt, ll = legend([("flag", None, "SPECIAL DEVICE")])
    lines = ll
    for i in range(5):
        lines += shape("flag", 5 + 2 * i, 8)
    est = service.create_estimate(db, CTX, "Jones power")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "flags.pdf", [plan(lt, lines)])),
                      confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


@pytest.fixture(autouse=True)
def _skip_mobile_tour(db):
    """Pre-skip the mobile tour for the owner and field users.

    The tour autostarts on first open of #/m/reviews and its popup can cover the
    queue controls; skipping it here (the same row the tour Skip button writes)
    keeps the tests on the queue itself. The tour itself is covered by S18.
    (tour.js tourShow now preserves a same-path ?kind= filter, so the pre-skip
    is belt-and-braces, not a workaround for a dropped filter.)"""
    for user_id in ("owner", "field"):
        db.execute("INSERT INTO help_progress (user_id, tour_id, status, updated_at)"
                   " VALUES (?, 'mobile', 'skipped', '2026-11-09T00:00:00+00:00')"
                   " ON CONFLICT (user_id, tour_id) DO UPDATE SET status = 'skipped'",
                   (user_id,))
    db.commit()


def open_reviews(pg, query=""):
    url = pg.base + "?embed=1#/m/reviews" + query
    pg.goto(url)
    pg.wait_for_selector("#mrev-card")
    dismiss_tour(pg)
    if query and query.lstrip("?") not in pg.url:
        # The mobile tour already dropped the filter once (see _skip_mobile_tour): the tour is skipped now,
        # so a full reload opens the filtered queue fresh.
        pg.goto(url)
        pg.reload()
        pg.wait_for_selector("#mrev-card")
        dismiss_tour(pg)


def picture_loaded(pg):
    pg.wait_for_function("() => { const i = document.querySelector('img#mrev-picture');"
                         " return i && i.complete && i.naturalWidth > 0; }")


def waiting(pg):
    return pg.inner_text("#mrev-waiting")


def card_id(pg):
    return pg.get_attribute("#mrev-card", "data-id")


def wait_next_card(pg, first):
    """After a decision the page reloads the queue: wait for a different item (the card is briefly gone meanwhile)."""
    pg.wait_for_function(f"() => {{ const c = document.querySelector('#mrev-card'); return c && c.dataset.id !== '{first}'; }}")



def position(pg):
    return pg.inner_text("#mrev-position")


def approve_current(pg):
    """Tap Approve, check it asked first, say Yes, and wait for the next item. Returns the new waiting text."""
    first = card_id(pg)
    pg.tap("#mrev-approve")
    pg.wait_for_selector("#mrev-confirm-box")
    assert "approve" in pg.inner_text("#mrev-confirm-box").lower()
    answer_yes(pg, "mrev")
    wait_next_card(pg, first)
    return waiting(pg)


def swipe(pg, direction):
    """A horizontal swipe across the card (left/right), or a vertical drag (up/down) that must not swipe."""
    b = pg.locator("#mrev-card").bounding_box()
    if direction == "left":
        x0, x1, y = b["x"] + b["width"] - 20, b["x"] + 20, b["y"] + b["height"] / 2
    elif direction == "right":
        x0, x1, y = b["x"] + 20, b["x"] + b["width"] - 20, b["y"] + b["height"] / 2
    else:  # vertical: straight down the middle of the card
        x0 = x1 = b["x"] + b["width"] / 2
        y = b["y"] + b["height"] / 2
        pg.mouse.move(x0, y)
        pg.mouse.down()
        for step in range(1, 7):
            pg.mouse.move(x0, y + step * 25)
        pg.mouse.up()
        return
    pg.mouse.move(x0, y)
    pg.mouse.down()
    for step in range(1, 9):
        pg.mouse.move(x0 + (x1 - x0) * step / 8, y)
    pg.mouse.up()


def fits(pg, width):
    """The phone/tablet page fits its screen: no sideways scroll, picture and buttons inside the viewport."""
    assert pg.evaluate("document.documentElement.scrollWidth") <= width
    box = pg.locator("#mrev-card").bounding_box()
    assert box and box["x"] >= 0 and box["x"] + box["width"] <= width + 1, box
    btn = pg.locator("#mrev-approve").bounding_box()
    assert btn and btn["height"] >= 56 and btn["x"] >= 0 and btn["x"] + btn["width"] <= width + 1, btn


# ------------------------------------------------------------------ M2: approve ten in a row by thumb

def test_E2E_S13_M2_approve_ten_in_a_row(phone, many_symbols):
    open_reviews(phone, "?kind=symbol")
    picture_loaded(phone)
    assert position(phone) == "1 of 12" and "12 symbols" in waiting(phone)
    for n in range(12, 2, -1):
        fits(phone, 390)
        approve_current(phone)
        assert position(phone) == f"1 of {n - 1}" and f"{n - 1} symbols" in waiting(phone)
    assert "2 symbols" in waiting(phone)


# ------------------------------------------------------------------ M3: swipe guards

def test_E2E_S13_M3_swipe_guards(phone, job):
    open_reviews(phone, "?kind=symbol")
    picture_loaded(phone)
    assert position(phone) == "1 of 5" and "5 symbols" in waiting(phone)
    first = card_id(phone)
    # A vertical scroll doesn't trigger a swipe: no confirm box, same item, same position.
    swipe(phone, "down")
    phone.wait_for_timeout(500)
    assert phone.locator("#mrev-confirm-box").count() == 0
    assert card_id(phone) == first and position(phone) == "1 of 5"
    # Swiping right asks first: Cancel, and nothing changes.
    swipe(phone, "right")
    phone.wait_for_selector("#mrev-confirm-box")
    assert "approve" in phone.inner_text("#mrev-confirm-box").lower()
    phone.click("#mrev-cancel")
    phone.wait_for_selector("#mrev-confirm-box", state="detached")
    assert card_id(phone) == first and position(phone) == "1 of 5" and "5 symbols" in waiting(phone)
    # Swiping left asks first too, and Yes takes it out.
    swipe(phone, "left")
    phone.wait_for_selector("#mrev-confirm-box")
    assert "out of the count" in phone.inner_text("#mrev-confirm-box")
    answer_yes(phone, "mrev")
    wait_next_card(phone, first)
    assert position(phone) == "1 of 4" and "4 symbols" in waiting(phone)


# ------------------------------------------------------------------ M4: phone relabel, desktop agrees

def test_E2E_S13_M4_phone_relabel_desktop_agrees(page, phone, flags_only):
    open_reviews(phone, "?kind=symbol")
    picture_loaded(phone)
    assert position(phone) == "1 of 5" and "5 symbols" in waiting(phone)
    # Relabel with "every identical match on this plan set".
    phone.tap("#mrev-relabel")
    phone.wait_for_selector("#mrev-relabel-box")
    phone.select_option("#mrev-type", "floor_box")
    phone.check("#mrev-all")
    phone.tap("#mrev-relabel-go")
    answer_yes(phone, "mrev")
    # Relabelling approves the symbols (status='approved'), so they leave the phone queue, which only lists
    # proposed ones: the phone ends with nothing waiting.
    phone.wait_for_selector("#mrev-empty")
    assert "Nothing waiting." in waiting(phone)
    # The desktop Reviews screen agrees: all five are floor boxes now, none unknown.
    page.goto(page.base + f"#/reviews/{flags_only['plan_set_id']}")
    page.wait_for_selector("#symrev-grid")
    dismiss_tour(page)
    page.wait_for_function("() => document.querySelectorAll('#symrev-grid .sym-card').length === 5")
    assert page.locator("#symrev-types [data-type=unknown]").count() == 0
    assert int(page.inner_text("#symrev-types [data-type=floor_box] .num")) == 5
    page.click("#symrev-types [data-type=floor_box]")
    page.wait_for_function("() => document.querySelectorAll('#symrev-grid .sym-card').length === 5")
    assert "floor box" in page.inner_text("#symrev-grid").lower()


# ------------------------------------------------------------------ M5: phone measurement approval

def test_E2E_S13_M5_phone_measurement_locked_and_priced(page, phone, job, db):
    open_reviews(phone, "?kind=measurement")
    assert position(phone) == "1 of 2"
    # Step to the room measurement (144.00 sqft KITCHEN), then approve it by thumb.
    if card_id(phone) != str(job["room_m"]):
        phone.tap("#mrev-next")
        phone.wait_for_function("() => document.querySelector('#mrev-position')?.textContent === '2 of 2'")
    assert card_id(phone) == str(job["room_m"])
    assert "144.00 sqft" in phone.inner_text("#mrev-card") and "KITCHEN" in phone.inner_text("#mrev-card")
    picture_loaded(phone)
    phone.tap("#mrev-approve")
    answer_yes(phone, "mrev")
    phone.wait_for_function("() => document.querySelector('#mrev-position')?.textContent === '1 of 1'")
    assert "1 measurement" in waiting(phone)
    # Locked on the desktop's Blueprint Review: the detail says approved and locked, and there's no Approve button.
    page.goto(page.base + f"#/takeoffs/{job['smith']}?m={job['room_m']}")
    page.wait_for_selector("#bp-viewer img.bp-tile", state="attached")
    page.wait_for_selector("#bp-detail")
    dismiss_tour(page)
    detail = page.inner_text("#bp-detail")
    assert "Approved" in detail and "locked" in detail
    assert page.locator("#bp-approve-one").count() == 0
    # Priced on the Estimate page: price flooring from the approved measurements.
    page.goto(page.base + f"#/estimates/{job['smith']}")
    page.wait_for_selector("#use-flooring")
    dismiss_tour(page)
    page.click("#use-flooring")
    answer_yes(page, "use")
    # The re-price lands async after Yes; wait for a visible quantity cell to read 144 (the hidden
    # line-measurement rows already mention 144 before the re-price, so textContent alone passes too early).
    page.wait_for_function("() => [...document.querySelectorAll('#lines-flooring tr[data-line] td:nth-child(2)')]"
                           ".some(td => td.textContent.includes('144'))")
    lines = page.inner_text("#lines-flooring")
    assert "144" in lines
    assert "$0.00" not in lines  # a priced line, not a zero line
    # The owner sees each line's cost and what the markups add on top, so qty x unit cost vs. price adds up.
    assert "Cost" in lines and "Price (with markups)" in lines
    note = page.locator("#lines-flooring [data-line-markup]").first.inner_text()
    assert note.startswith("cost $")
    # The trades tile counts trades only ("Other lines" added by hand isn't a trade).
    assert " ".join(page.inner_text("#tile-est-trades").split()).lower() == "1 trade"
    # Adding a line by hand: picking a price book item brings its kind too (labor stays labor, not the default material).
    page.click("#add-line summary")
    kinds = page.evaluate("""() => {
        const pick = document.querySelector('#line-pick'), kind = document.querySelector('#line-kind'), seen = [];
        for (const o of [...pick.options].slice(1)) {
            pick.value = o.value; pick.dispatchEvent(new Event('change')); seen.push(kind.value);
        }
        return seen;
    }""")
    assert "labor" in kinds and "material" in kinds
    assert "priced at 144 sqft" in page.inner_text("#sources-flooring")
    # The estimate's total at the bottom: each trade, then the total, the same as the total tile at the top.
    est = service.get_estimate(db, CTX, job["smith"])
    total = "${:,.2f}".format(est["totals"]["total_cents"] / 100)
    totals = page.inner_text("#estimate-totals")
    assert "Flooring" in totals and total in page.inner_text("#estimate-totals tr.total")
    # Approved, then reopened for changes in place: it asks first, goes back to draft, and lists what changed.
    service.set_status(db, CTX, job["smith"], est["rev"], "approved")
    db.commit()
    page.reload()
    page.wait_for_selector("#estimate-reopen")
    dismiss_tour(page)
    assert page.locator("#add-line").count() == 0                       # approved: no editing until it's reopened
    page.click("#estimate-reopen")
    page.fill("#reopen-why", "revise the answers")
    page.click("#reopen-go")
    answer_yes(page, "reopen")
    page.wait_for_selector("#since-approval")
    assert "Nothing has changed since it was approved" in page.inner_text("#since-approval")
    assert page.locator("#add-line").count() == 1 and page.locator("#estimate-reopen").count() == 0
    # The line's own price book item changes (2026-11-17, David): editing the line says so and fills it in on a click.
    from estimator.pricing.price_book import set_price
    est = service.get_estimate(db, CTX, job["smith"])
    ln = next(x for s in est["sections"] if s["module_id"] == "flooring" for x in s["lines"] if x["price_key"])
    set_price(db, "default", ln["price_key"], description="Flooring item, new price", kind=ln["kind"], unit=ln["unit"],
              cost_cents=ln["unit_cost_cents"] + 100, actor="owner")
    db.commit()
    page.reload()
    page.wait_for_selector(f"[data-line-edit='{ln['id']}']")
    dismiss_tour(page)
    page.click(f"[data-line-edit='{ln['id']}']")
    page.wait_for_selector(f"[data-line-drift='{ln['id']}']")
    page.click(f"#line-edit-use-book-{ln['id']}")
    new_cost = "{:.2f}".format((ln["unit_cost_cents"] + 100) / 100)
    assert page.input_value("tr.line-edit input[aria-label='Unit cost in dollars']") == new_cost
    page.click("tr.line-edit button:has-text('Cancel')")
    # Approved again and the customer accepted the quote; then they want more: a change order, on its own page.
    from estimator.bids import service as bids
    service.set_status(db, CTX, job["smith"], service.get_estimate(db, CTX, job["smith"])["rev"], "approved")
    quote = bids.generate(db, CTX, job["smith"], customer={"name": "Smith", "email": "smith@example.com"})
    bids.set_status(db, CTX, quote["id"], "won")
    db.commit()
    page.reload()
    page.wait_for_selector("#estimate-change-order")
    dismiss_tour(page)
    assert page.locator("#estimate-reopen").count() == 0                # accepted: a change order, not a reopen
    page.click("#estimate-change-order")
    page.fill("#change-order-why", "add the hallway")
    page.click("#change-order-go")
    answer_yes(page, "change-order")
    page.wait_for_selector("#change-order-of")
    banner = page.inner_text("#change-order-of")
    assert "Change order 1" in banner and quote["number"] in banner and "add the hallway" in banner


# ------------------------------------------------------------------ M6: tablet portrait + landscape

def test_E2E_S13_M6_tablet_layout(browser, site, job):
    problems = []
    for width, height in ((768, 1024), (1024, 768)):
        ctx = browser.new_context(viewport={"width": width, "height": height}, has_touch=True, is_mobile=True,
                                  device_scale_factor=2)
        pg = ctx.new_page()
        pg.set_default_timeout(15000)
        pg.on("pageerror", lambda e: problems.append("page error: " + str(e)))
        pg.on("response", lambda r: r.status >= 400 and problems.append(f"HTTP {r.status}: {r.url}"))
        pg.on("console", lambda m: m.type == "error" and problems.append("console error: " + m.text))
        pg.base = site
        try:
            open_reviews(pg, "?kind=symbol")
            picture_loaded(pg)
            start = int(position(pg).split(" of ")[1])  # the second orientation starts where the first left off
            assert f"{start} symbols" in waiting(pg)
            fits(pg, width)  # picture + buttons fit; nothing cut off
            # The buttons still work at this size: approve one by thumb.
            first = card_id(pg)
            pg.tap("#mrev-approve")
            answer_yes(pg, "mrev")
            wait_next_card(pg, first)
            assert position(pg) == f"1 of {start - 1}"
            fits(pg, width)
        finally:
            ctx.close()
    assert not problems, problems


# ------------------------------------------------------------------ M7: field staff, symbols only

def test_E2E_S13_M7_field_symbols_only(phone, job):
    with sign_in_as(phone, "field"):
        open_reviews(phone)
        picture_loaded(phone)
        # Symbols only: the waiting line counts no measurements, and every card stepped through is a symbol.
        assert "0 measurements" in waiting(phone)
        assert "5 symbols" in waiting(phone)
        # Field staff get no Skip button (it is only rendered for roles that can decide), so step with Next.
        for k in range(1, 5):
            assert phone.get_attribute("#mrev-card", "data-kind") == "symbol"
            phone.tap("#mrev-next")
            phone.wait_for_function(f"() => document.querySelector('#mrev-position')?.textContent === '{k + 1} of 5'")
        assert phone.get_attribute("#mrev-card", "data-kind") == "symbol"
        assert position(phone) == "5 of 5"  # stepped through all five; nothing was decided
        # No buttons: field staff look only.
        assert phone.locator("#mrev-approve").count() == 0
        assert phone.locator("#mrev-reject").count() == 0
        assert phone.locator("#mrev-relabel").count() == 0
        assert phone.locator("#mrev-look-only").count() == 1
        assert "You can look at these here" in phone.inner_text("#mrev-look-only")


# ------------------------------------------------------------------ M8: server-mode thumbnails on desktop Reviews

def test_E2E_S13_M8_server_mode_thumbnails(page, job, monkeypatch):
    """Server mode: no same-PC sign-in, so a plain <img src> would get 401. Signed in only by the Jobs app's token
    (localStorage ap_auth), the desktop Reviews thumbnails still load — as blob: URLs, the Sprint 13 B05 pattern.
    The literal Remote Access path stays manual."""
    from estimator.api import auth
    monkeypatch.setenv("ESTIMATOR_MODE", "server")
    auth.set_app_token_resolver(lambda tok: {"user_id": "maria", "role": "reviewer", "name": "Maria",
                                            "company_id": CTX.company_id} if tok == "phone-token" else None)
    try:
        page.add_init_script("localStorage.setItem('ap_auth', " + json.dumps(json.dumps(
            {"mode": "personal", "token": "phone-token"})) + ")")
        page.goto(page.base + f"#/reviews/{job['jones_ps']}")
        page.wait_for_selector("#symrev-grid")
        dismiss_tour(page)
        page.wait_for_function("() => [...document.querySelectorAll('#symrev-grid img.sym-thumb')]"
                               ".every(i => i.complete && i.naturalWidth > 0)")
        thumbs = page.locator("#symrev-grid img.sym-thumb")
        assert thumbs.count() == 5
        for i in range(5):
            assert page.evaluate(f"() => document.querySelectorAll('#symrev-grid img.sym-thumb')[{i}].src"
                                 ).startswith("blob:")
        assert page.locator("#symrev-approve").count() == 1  # a reviewer decides
    finally:
        auth.set_app_token_resolver(None)