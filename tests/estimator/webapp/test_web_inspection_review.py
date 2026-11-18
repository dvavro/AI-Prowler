"""Webapp: the Inspector's code review endpoints and the estimate detail page.

A fake provider stands in for Claude, Grok and Muse: no real API calls, no
token cost. The zip lookup is served from the seeded zip_cache: no network.
"""
import json
from pathlib import Path

import pytest

from estimator.agents import providers, roles
from estimator.context import personal_context
from estimator.estimating import quick, service

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
CTX = personal_context()
ADDR = "1500 Shadow Pines Dr, New Smyrna Beach, FL 32168"
ELEC = {"outlets": 10, "switches": 4, "lights": 6, "gfci": 0}
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
MARKERS = ["inspection-review-", "inspection-jurisdiction-", "inspection-zip-",
           "inspection-run-", "inspection-checklist-", "Inspection review"]


class FakeTextProvider:
    """Answers like Claude or Grok would. ask_vision must never be called."""

    def __init__(self):
        self.replies = {"claude_api": []}
        self.calls = []

    def ready(self, provider):
        return True, ""

    def model_for(self, provider):
        return "claude-sonnet-5-5"

    def ask(self, provider, system, user, model=""):
        self.calls.append({"provider": provider, "system": system, "user": user, "model": model})
        r = self.replies[provider].pop(0) if self.replies[provider] else "{}"
        if isinstance(r, Exception):
            raise r
        return r, {"input": 3000, "output": 200}

    def ask_vision(self, provider, system, user, images, model=""):
        raise AssertionError("the inspection review must use ask, not ask_vision")

    def cost(self, model, usage):
        return round((usage["input"] * 2 + usage["output"] * 10) / 1_000_000, 5)


@pytest.fixture
def fake():
    f = FakeTextProvider()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


@pytest.fixture
def elec(db):
    db.execute("INSERT INTO zip_cache (zip_code, city, state, state_abbr, looked_up_at)"
               " VALUES ('32168', 'New Smyrna Beach', 'Florida', 'FL', '2026-11-18T10:00:00+00:00')")
    e = service.create_estimate(db, CTX, "Electrical test", address=ADDR)
    return quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])


@pytest.fixture
def multi(db):
    db.execute("INSERT INTO zip_cache (zip_code, city, state, state_abbr, looked_up_at)"
               " VALUES ('32168', 'New Smyrna Beach', 'Florida', 'FL', '2026-11-18T10:00:00+00:00')")
    e = service.create_estimate(db, CTX, "Two trades", address=ADDR)
    e = quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])
    return quick.answer(db, CTX, e["id"], "roofing", ROOF, e["rev"])


def _on(db, provider="claude_api"):
    return roles.update_role(db, CTX, "inspector", {"provider": provider}, confirm=True)


def _reply(*items):
    return json.dumps({"checklist": list(items)})


GFCI_ITEM = {"id": "gfci", "description": "GFCI protection in bathrooms, kitchens, garage, laundry, outdoors",
             "code_ref": "210.8", "status": "missing", "note": "no GFCI outlets priced",
             "suggested_action": {"price_key": "el_gfci_ea", "quantity": 2, "unit": "ea",
                                  "description": "GFCI outlets"}}
ROOF_ITEM = {"id": "underlayment", "description": "Underlayment per R905.1.1",
             "code_ref": "R905.1.1", "status": "pass", "note": "self-adhering underlayment priced"}
AFCI_ITEM = {"id": "afci", "description": "AFCI protection on bedroom and living-area circuits",
             "code_ref": "210.12", "status": "flag", "note": "bedroom circuits not broken out"}


# ------------------------------------------------------------------ the endpoints

def test_post_runs_a_review_and_get_returns_it(call, db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM)]
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review", {})
    assert r.status == 200, r.json()
    out = r.json()
    assert out["reviews"][0]["module_id"] == "electrical"
    assert out["reviews"][0]["zip_code"] == "32168"
    assert out["reviews"][0]["code_edition"] == "2020"              # Florida, November 2026
    assert out["reviews"][0]["checklist"][0]["id"] == "gfci"

    r = call("GET", f"{API}/estimates/{elec['id']}/inspection-review")
    assert r.status == 200, r.json()
    got = r.json()
    assert [x["module_id"] for x in got["reviews"]] == ["electrical"]
    assert got["reviews"][0]["id"] == out["reviews"][0]["id"]


def test_post_reviews_every_trade_and_module_id_reviews_one(call, db, multi, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM), _reply(ROOF_ITEM)]
    r = call("POST", f"{API}/estimates/{multi['id']}/inspection-review", {})
    assert r.status == 200, r.json()
    out = r.json()
    assert [x["module_id"] for x in out["reviews"]] == ["electrical", "roofing"]
    assert out["reviews"][1]["code_edition"] == "8th Edition"
    assert out["reviews"][1]["jurisdiction"]["edition"]["code"] == "Florida Building Code 8th Edition"

    fake.replies["claude_api"] = [_reply(ROOF_ITEM)]
    r = call("POST", f"{API}/estimates/{multi['id']}/inspection-review", {"module_id": "roofing"})
    assert r.status == 200, r.json()
    out = r.json()
    assert [x["module_id"] for x in out["reviews"]] == ["roofing"]
    assert len(fake.calls) == 3                                     # two for the first run, one for this one


def test_post_refuses_a_services_only_estimate(call, db, fake):
    e = service.create_estimate(db, CTX, "Windows", address=ADDR)
    e = quick.answer(db, CTX, e["id"], "window_cleaning", {"windows": 10}, e["rev"])
    _on(db)
    r = call("POST", f"{API}/estimates/{e['id']}/inspection-review", {})
    assert r.status == 400
    assert "no trade with an inspection checklist" in r.json()["message"]


def test_post_refuses_when_the_role_is_off(call, db, elec, fake):
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review", {})
    assert r.status == 400
    assert "off" in r.json()["message"]
    assert fake.calls == []                                         # refused before any LLM call


def test_apply_adds_the_suggested_item(call, db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM)]
    review = call("POST", f"{API}/estimates/{elec['id']}/inspection-review", {}).json()["reviews"][0]
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review/{review['id']}/apply",
             {"item_id": "gfci", "rev": elec["rev"]})
    assert r.status == 200, r.json()
    detail = call("GET", f"{API}/estimates/{elec['id']}/detail").json()
    custom = next(s for s in detail["estimate"]["sections"] if s["module_id"] == "custom")
    line = next(ln for ln in custom["lines"] if ln["price_key"] == "el_gfci_ea")
    assert line["quantity"] == "2" and line["unit"] == "ea"


def test_apply_refuses_an_item_with_no_suggestion(call, db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(AFCI_ITEM)]
    review = call("POST", f"{API}/estimates/{elec['id']}/inspection-review", {}).json()["reviews"][0]
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review/{review['id']}/apply",
             {"item_id": "afci", "rev": elec["rev"]})
    assert r.status == 400
    assert "no item to add" in r.json()["message"]


def test_apply_refuses_an_unknown_review(call, db, elec, fake):
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review/999/apply",
             {"item_id": "gfci", "rev": elec["rev"]})
    assert r.status == 404


# ------------------------------------------------------------------ the detail page

def test_detail_carries_inspector_and_reviews(call, db, multi, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM), _reply(ROOF_ITEM)]
    call("POST", f"{API}/estimates/{multi['id']}/inspection-review", {})
    detail = call("GET", f"{API}/estimates/{multi['id']}/detail").json()
    insp = detail["inspector"]
    assert insp["enabled"] is True and insp["provider"] == "claude_api"
    assert detail["reviewable_trades"] == ["electrical", "roofing"]
    # latest per trade, newest first (the UI looks each trade up by module_id)
    assert [x["module_id"] for x in detail["inspection_reviews"]] == ["roofing", "electrical"]
    by_trade = {x["module_id"]: x for x in detail["inspection_reviews"]}
    assert by_trade["electrical"]["checklist"][0]["id"] == "gfci"
    assert by_trade["roofing"]["checklist"][0]["id"] == "underlayment"


def test_detail_carries_no_reviews_when_none_exist(call, db, multi, fake):
    detail = call("GET", f"{API}/estimates/{multi['id']}/detail").json()
    assert detail["inspection_reviews"] == []
    assert detail["reviewable_trades"] == ["electrical", "roofing"]
    assert detail["inspector"]["enabled"] is False


def test_ui_has_the_review_markers():
    """The per-trade card exists in the shipped estimates.js."""
    js = (WEB / "estimates.js").read_text(encoding="utf-8")
    for marker in MARKERS:
        assert marker in js, marker
    assert "inspectionReviewCard(d, sec, msg)" in js
