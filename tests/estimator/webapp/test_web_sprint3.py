"""Coder 2 Sprint 3: the basic Price Book screen (pricebook_get / pricebook_update / pricebook_import with pasted CSV).
Every money change asks first, exactly like the MCP tools; costs are only shown to the roles that open the screen."""
import json

import pytest

API = "/estimator-api"
KEY = "pw_driveway_sqft"


def _price(call, key=KEY, headers=None):
    book = call("GET", f"{API}/price-book?module_id=pressure_washing", headers=headers).json()
    return next(p for p in book["prices"] if p["price_key"] == key)


def test_price_book_lists_samples_until_set(call):
    book = call("GET", f"{API}/price-book").json()
    assert book["count"] > 10 and book["samples_left"] == book["count"]
    p = _price(call)
    assert p["sample"] is True and p["unit"] and p["cost_cents"] > 0
    only = call("GET", f"{API}/price-book?module_id=pressure_washing&samples_only=1").json()
    assert all(x["sample"] for x in only["prices"]) and all(x["module_id"] == "pressure_washing" for x in only["prices"])
    assert call("GET", f"{API}/price-book?module_id=unicorn_grooming").status == 404


def test_changing_a_price_asks_first_with_old_and_new(call):
    old = _price(call)["cost_cents"]
    r = call("POST", f"{API}/price-book", {"prices": {KEY: "0.21"}})
    assert r.status == 200
    ask = r.json()
    assert ask["needs_confirmation"] is True and "confirm=true" not in ask["question"]
    assert ask["changes"] == [{**ask["changes"][0], "price_key": KEY, "old_cents": old, "new_cents": 21}]
    assert _price(call)["sample"] is True                      # nothing saved yet
    done = call("POST", f"{API}/price-book", {"prices": {KEY: "0.21"}, "confirm": True}).json()
    assert done["changed"][0]["new_cents"] == 21
    p = _price(call)
    assert p["cost_cents"] == 21 and p["sample"] is False and p["source"] == "yours"


def test_confirm_must_be_true_not_truthy(call):
    r = call("POST", f"{API}/price-book", {"prices": {KEY: "0.30"}, "confirm": "yes"}).json()
    assert r["needs_confirmation"] is True and _price(call)["sample"] is True


def test_bad_price_changes(call):
    for body, code, words in (
        ({"prices": {}}, 400, "at least one"),
        ({"prices": "0.2"}, 400, "at least one"),
        ({"prices": {KEY: "lots"}}, 400, "dollars"),
        ({"prices": {KEY: "-1"}}, 400, "negative"),
        ({"prices": {"no_such_price": "1"}}, 404, "no price called"),
        ({"prices": {KEY: "1"}, "effective_date": "next week"}, 400, "YYYY-MM-DD"),
    ):
        r = call("POST", f"{API}/price-book", body)
        assert r.status == code and words in r.json()["message"], (body, r.body)


def test_future_dated_price(call):
    call("POST", f"{API}/price-book", {"prices": {KEY: "0.40"}, "effective_date": "2099-01-01", "confirm": True})
    assert _price(call)["sample"] is True                      # not in effect yet


def test_price_changes_reach_live_updates_and_are_logged(call):
    cur = call("GET", f"{API}/updates").json()["cursor"]
    call("POST", f"{API}/price-book", {"prices": {KEY: "0.22"}, "confirm": True})
    evs = call("GET", f"{API}/updates?since={cur}").json()["events"]
    assert any(e["action"] == "prices_changed" for e in evs)


def test_import_pasted_csv_previews_then_saves(call):
    csv = "Item Code,Description,Unit,Unit Price\npw_driveway_sqft,Driveway,sqft,0.19\nbogus,Nothing like this,ea,5\n"
    ask = call("POST", f"{API}/price-book/import", {"csv_text": csv}).json()
    assert ask["needs_confirmation"] is True and ask["updates"] == 1 and ask["skipped"] == 1
    assert any("pw_driveway_sqft" in c for c in ask["changes"])     # lines are ready-made sentences
    assert ask["skipped_rows"][0]["row"] == 3
    assert _price(call)["sample"] is True
    done = call("POST", f"{API}/price-book/import", {"csv_text": csv, "confirm": True}).json()
    assert done["saved"] == 1 and _price(call)["cost_cents"] == 19


def test_import_add_new(call):
    csv = "Description,Unit,Cost\nGutter guard,lf,3.50\n"
    assert call("POST", f"{API}/price-book/import", {"csv_text": csv}).json().get("saved", 0) == 0
    done = call("POST", f"{API}/price-book/import", {"csv_text": csv, "add_new": True, "confirm": True}).json()
    assert done["saved"] == 1
    keys = [p["price_key"] for p in call("GET", f"{API}/price-book").json()["prices"]]
    assert any(k.startswith("custom_gutter") for k in keys)


def test_import_bad_input(call):
    assert call("POST", f"{API}/price-book/import", {"csv_text": "  "}).status == 400
    assert call("POST", f"{API}/price-book/import", {"csv_text": "a,b\n1,2", "mapping": "cost=b"}).status == 400
    r = call("POST", f"{API}/price-book/import", {"csv_text": "Name,Colour\nx,red\n"})
    assert r.status == 400 and "cost" in r.json()["message"]


@pytest.mark.parametrize("role", ["reviewer", "office", "field"])
def test_only_owner_and_estimator_see_costs(call, session_for, role):
    h = session_for(role)
    assert call("GET", f"{API}/price-book", headers=h).status == 403
    assert call("POST", f"{API}/price-book", {"prices": {KEY: "1"}}, headers=h).status == 403
    assert call("POST", f"{API}/price-book/import", {"csv_text": "a\n1"}, headers=h).status == 403
    me = call("GET", f"{API}/me", headers=h).json()["me"]
    assert "price_book" not in [s["id"] for s in me["menu"]]


def test_estimator_can_change_prices(call, session_for):
    h = session_for("estimator")
    r = call("POST", f"{API}/price-book", {"prices": {KEY: "0.25"}, "confirm": True}, headers=h)
    assert r.status == 200 and r.json()["changed"][0]["new_cents"] == 25


def test_prices_are_per_company(call, session_for):
    call("POST", f"{API}/price-book", {"prices": {KEY: "0.33"}, "confirm": True})
    other = _price(call, headers=session_for("owner", company="other-co"))
    assert other["sample"] is True and other["cost_cents"] != 33


def test_price_book_needs_the_app_header(call):
    r = call("POST", f"{API}/price-book", {"prices": {KEY: "1"}, "confirm": True}, write_header=False)
    assert r.status == 403 and r.json()["error"] == "csrf"
    assert _price(call)["sample"] is True


def test_price_book_screen_is_ready_and_drawn():
    from estimator.api import nav, router
    assert next(s for s in nav.SCREENS if s["id"] == "price_book")["status"] == "ready"
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert "price_book: renderPriceBook" in js and "/price-book/import" in js


def test_question_strips_the_ai_instructions():
    from estimator.api.router import _question
    assert _question("Change these prices? a: $1 → $2. Call again with confirm=true once the user says yes.") == \
        "Change these prices? a: $1 → $2."
    assert _question("Import 1 change? Show the user the changes, then call again with confirm=true.") == "Import 1 change?"
    assert json.dumps(_question("Attach x?")) == '"Attach x?"'
