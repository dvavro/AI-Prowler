"""Coder 2 Sprint 13 browser tests (Tester 2): reviews on a phone - one item at a time on a 390 x 844 touch screen,
approve by tapping, take out by swiping, relabel, measurements, and pictures sent with the Jobs app's token.

    run_tests_estimator.bat browser [--human]
"""
import json

import pytest

from browser_helpers import HUMAN, answer_yes
from e2e_helpers import dismiss_tour
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from pdfmaker import make_pdf, title_block
from test_plan_engine_sprint10 import legend, plan, shape

CTX = personal_context()
QUARTER = 'SCALE: 1/4" = 1\'-0"'


def _square(x, y, size):
    return [(x, y, x + size, y), (x + size, y, x + size, y + size), (x + size, y + size, x, y + size), (x, y + size, x, y)]


@pytest.fixture
def job(db, tmp_path):
    """Jones power: 3 receptacles and 2 symbols the legend doesn't name. Smith house: a 12 x 12 ft KITCHEN measured from
    the room (to approve) and a typed floor area (no place on the plan)."""
    from estimator.takeoff import measurements as ms
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
    db.commit()
    return {"jones": jones["id"], "smith": smith["id"], "room_m": m["proposed"][0]["id"]}


@pytest.fixture(autouse=True)
def _skip_mobile_tour(db):
    """Pre-skip the mobile tour for the owner and field users, so its pop-up can never cover a phone control.

    Same row the tour Skip button writes; the tour itself is covered by S18. tour.js also preserves a
    same-path ?kind= filter when a tour step navigates, so the filter survives even if the tour runs."""
    for user_id in ("owner", "field"):
        db.execute("INSERT INTO help_progress (user_id, tour_id, status, updated_at)"
                   " VALUES (?, 'mobile', 'skipped', '2026-11-09T00:00:00+00:00')"
                   " ON CONFLICT (user_id, tour_id) DO UPDATE SET status = 'skipped'",
                   (user_id,))
    db.commit()


def open_reviews(pg, query=""):
    pg.goto(pg.base + "?embed=1#/m/reviews" + query)
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


# ------------------------------------------------------------------ symbols                         C2S13-B01..B03

def test_approve_a_symbol_by_tapping(phone, job):                                  # C2S13-B01
    open_reviews(phone, "?kind=symbol")
    picture_loaded(phone)
    assert phone.inner_text("#mrev-position") == "1 of 5" and "5 symbols" in waiting(phone)
    assert phone.evaluate("document.documentElement.scrollWidth") <= 390           # fits the phone, no sideways scroll
    box = phone.locator("#mrev-approve").bounding_box()
    assert box["height"] >= 56 and box["width"] >= 120                              # thumb-sized
    first = card_id(phone)
    phone.tap("#mrev-approve")
    answer_yes(phone, "mrev")                                                       # asks first
    wait_next_card(phone, first)
    assert phone.inner_text("#mrev-position") == "1 of 4" and "4 symbols" in waiting(phone)


def test_take_out_by_swiping_left(phone, job):                                     # C2S13-B02
    open_reviews(phone, "?kind=symbol")
    first = card_id(phone)
    b = phone.locator("#mrev-card").bounding_box()
    y = b["y"] + b["height"] / 2
    phone.mouse.move(b["x"] + b["width"] - 20, y)
    phone.mouse.down()
    for step in range(1, 9):
        phone.mouse.move(b["x"] + b["width"] - 20 - step * 30, y)
    phone.mouse.up()
    phone.wait_for_selector("#mrev-confirm-box")
    assert "out of the count" in phone.inner_text("#mrev-confirm-box")                # swiping left asks to take it out
    answer_yes(phone, "mrev")
    wait_next_card(phone, first)
    assert "4 symbols" in waiting(phone)


def test_relabel_and_skip(phone, job):                                             # C2S13-B03
    open_reviews(phone, "?kind=symbol")
    first = card_id(phone)
    phone.tap("#mrev-skip")
    phone.wait_for_function("() => document.querySelector('#mrev-position').textContent === '2 of 5'")
    assert card_id(phone) != first and "5 symbols" in waiting(phone)                # skip changes nothing
    phone.tap("#mrev-prev")
    phone.wait_for_function("() => document.querySelector('#mrev-position').textContent === '1 of 5'")
    phone.tap("#mrev-relabel")
    phone.select_option("#mrev-type", "floor_box")
    phone.tap("#mrev-relabel-go")
    answer_yes(phone, "mrev")
    wait_next_card(phone, first)


# ------------------------------------------------------------------ measurements                     C2S13-B04

def test_approve_a_measurement_and_see_a_typed_one(phone, job):                    # C2S13-B04
    open_reviews(phone, "?kind=measurement")
    assert phone.inner_text("#mrev-position") == "1 of 2"
    titles = []
    for _ in range(2):
        titles.append((card_id(phone), phone.inner_text("#mrev-card")))
        if phone.locator("img#mrev-picture").count():
            picture_loaded(phone)
        else:
            assert "Typed in" in phone.inner_text("#mrev-picture")
        if phone.inner_text("#mrev-position") == "1 of 2":
            phone.tap("#mrev-next")
            phone.wait_for_function("() => document.querySelector('#mrev-position').textContent === '2 of 2'")
    assert any("144.00 sqft" in t and "KITCHEN" in t for _, t in titles)
    if titles[0][0] == str(job["room_m"]):                                          # back to the room measurement
        phone.tap("#mrev-prev")
    phone.wait_for_function(f"() => document.querySelector('#mrev-card')?.dataset.id === '{job['room_m']}'")
    phone.tap("#mrev-approve")
    answer_yes(phone, "mrev")
    phone.wait_for_function("() => document.querySelector('#mrev-position').textContent === '1 of 1'")
    assert "1 measurements" in waiting(phone) or "1 measurement" in waiting(phone)


# ------------------------------------------------------------------ signed in by the Jobs app        C2S13-B05

def test_pictures_load_with_the_jobs_app_token(phone, job, monkeypatch):          # C2S13-B05
    """Server mode: no same-PC sign-in, so a plain <img src> would get 401. Signed in only by the Jobs app's token
    (localStorage ap_auth), the page and its pictures still load."""
    from estimator.api import auth
    monkeypatch.setenv("ESTIMATOR_MODE", "server")
    auth.set_app_token_resolver(lambda tok: {"user_id": "maria", "role": "reviewer", "name": "Maria",
                                             "company_id": CTX.company_id} if tok == "phone-token" else None)
    try:
        phone.add_init_script("localStorage.setItem('ap_auth', " + json.dumps(json.dumps(
            {"mode": "personal", "token": "phone-token"})) + ")")
        open_reviews(phone, "?kind=symbol")
        picture_loaded(phone)
        assert phone.evaluate("document.querySelector('img#mrev-picture').src").startswith("blob:")
        assert phone.locator("#mrev-approve").count() == 1                         # a reviewer decides
    finally:
        auth.set_app_token_resolver(None)


def test_empty_queue(phone, db):                                                    # C2S13-B06
    phone.goto(phone.base + "?embed=1#/m/reviews")
    phone.wait_for_selector("#mrev-empty")
    assert "All checked" in phone.inner_text("#mrev-empty") and "Nothing waiting" in waiting(phone)
    if HUMAN:
        phone.wait_for_timeout(800)
