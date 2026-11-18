"""The Inspector agent on the Estimates screen: run, read, apply (web API + JS markers).

A fake provider stands in for Claude, Grok and Muse: no real API calls, no
token cost. The zip lookup is served from the seeded zip_cache: no network.
"""
import json

import pytest

from estimator.agents import providers, roles
from estimator.api import router
from estimator.context import personal_context
from estimator.estimating import quick, service
from estimator.estimating.zip_lookup import nec_edition

API = "/estimator-api"
CTX = personal_context()
NOW = "2026-11-18T10:00:00+00:00"
ELEC = {"outlets": 10, "switches": 4, "lights": 6}
ADDR = "1500 Shadow Pines Dr, New Smyrna Beach, FL 32168"


class FakeTextProvider:
    """Answers like Claude or Grok would. replies[provider] is a list of texts
    (or exceptions) used in order."""

    def __init__(self):
        self.keys = {"claude_api": True, "grok_api": True, "muse_api": True}
        self.replies = {"claude_api": [], "grok_api": [], "muse_api": []}
        self.calls = []

    def ready(self, provider):
        return (True, "") if self.keys.get(provider) else (False, "no API key saved")

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3",
                "muse_api": "muse-spark-1.3"}[provider]

    def ask(self, provider, system, user, model=""):
        self.calls.append({"provider": provider, "system": system, "user": user, "model": model})
        r = self.replies[provider].pop(0) if self.replies[provider] else "{}"
        if isinstance(r, Exception):
            raise r
        return r, {"input": 3000, "output": 200}

    def cost(self, model, usage):           # $2 / $10 per 1M tokens, like Sonnet
        return round((usage["input"] * 2 + usage["output"] * 10) / 1_000_000, 5)


@pytest.fixture
def fake():
    f = FakeTextProvider()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


@pytest.fixture
def elec(db):
    """An electrical estimate in New Smyrna Beach, with the zip cached (no network)."""
    db.execute("INSERT INTO zip_cache (zip_code, city, state, state_abbr, looked_up_at)"
               " VALUES ('32168', 'New Smyrna Beach', 'Florida', 'FL', ?)", (NOW,))
    e = service.create_estimate(db, CTX, "Electrical test", address=ADDR)
    return quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "inspector", {"provider": provider, **extra}, confirm=True)


def _reply(*items):
    return json.dumps({"checklist": list(items)})


GFCI_ITEM = {"id": "gfci", "description": "GFCI protection in bathrooms, kitchens, garage, laundry, outdoors",
             "code_ref": "210.8", "status": "missing", "note": "no GFCI outlets priced",
             "suggested_action": {"price_key": "el_gfci_ea", "quantity": 2, "unit": "ea",
                                  "description": "GFCI outlets"}}
AFCI_ITEM = {"id": "afci", "description": "AFCI protection on bedroom and living-area circuits",
             "code_ref": "210.12", "status": "flag", "note": "bedroom circuits not broken out"}


def _run(call, eid, **body):
    r = call("POST", f"{API}/estimates/{eid}/inspection-review", body)
    assert r.status == 200, r.json()
    return r.json()


# ------------------------------------------------------------------ run and read

def test_run_review_returns_a_checklist_and_stores_it(call, db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM, AFCI_ITEM)]
    out = _run(call, elec["id"])
    assert out["zip_code"] == "32168" and out["status"] == "complete"
    assert out["jurisdiction"]["city"] == "New Smyrna Beach"
    assert out["nec_edition"] == nec_edition("FL")["edition"]
    assert [i["id"] for i in out["checklist"]] == ["gfci", "afci"]
    assert db.execute("SELECT COUNT(*) FROM inspection_reviews").fetchone()[0] == 1


def test_get_review_returns_the_latest(call, db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(AFCI_ITEM), _reply(GFCI_ITEM)]
    first = _run(call, elec["id"])
    second = _run(call, elec["id"])
    got = call("GET", f"{API}/estimates/{elec['id']}/inspection-review").json()
    assert got["review"]["id"] == second["id"] != first["id"]
    assert got["review"]["checklist"][0]["id"] == "gfci"


def test_get_review_with_none_returns_null(call, elec):
    assert call("GET", f"{API}/estimates/{elec['id']}/inspection-review").json() == {
        "ok": True, "review": None}


def test_run_review_with_the_role_off_is_refused(call, elec, fake):
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review", {})
    assert r.status == 400 and "off" in r.json()["message"]


def test_run_review_on_a_non_electrical_estimate_is_refused(call, db, fake):
    e = service.create_estimate(db, CTX, "Roof")
    e = quick.answer(db, CTX, e["id"], "roofing",
                     {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}, e["rev"])
    _on(db)
    r = call("POST", f"{API}/estimates/{e['id']}/inspection-review", {})
    assert r.status == 400 and "no electrical section" in r.json()["message"]


def test_run_review_without_a_zip_is_refused(call, db, fake):
    e = service.create_estimate(db, CTX, "No address")
    e = quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])
    _on(db)
    r = call("POST", f"{API}/estimates/{e['id']}/inspection-review", {})
    assert r.status == 400 and "no zip code" in r.json()["message"]


def test_run_review_as_office_is_refused(call, db, elec, fake, session_for):
    _on(db)
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review", {},
             headers=session_for("office"))
    assert r.status == 403 and r.json()["error"] == "permission_denied"


# ------------------------------------------------------------------ apply

def test_apply_adds_the_suggested_line(call, db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM, AFCI_ITEM)]
    review = _run(call, elec["id"])
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review/{review['id']}/apply",
             {"item_id": "gfci", "rev": elec["rev"]})
    assert r.status == 200, r.json()
    custom = next(s for s in r.json()["sections"] if s["module_id"] == "custom")
    line = next(ln for ln in custom["lines"] if ln["price_key"] == "el_gfci_ea")
    assert line["description"] == "GFCI outlets" and line["quantity"] == "2"


def test_apply_with_no_suggestion_is_refused(call, db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM, AFCI_ITEM)]
    review = _run(call, elec["id"])
    r = call("POST", f"{API}/estimates/{elec['id']}/inspection-review/{review['id']}/apply",
             {"item_id": "afci", "rev": elec["rev"]})
    assert r.status == 400 and "no item to add" in r.json()["message"]


# ------------------------------------------------------------------ detail and the page

def test_detail_includes_the_inspector_setting_and_the_latest_review(call, db, elec, fake):
    detail = call("GET", f"{API}/estimates/{elec['id']}/detail").json()
    assert detail["inspector"]["enabled"] is False and detail["inspection_review"] is None
    _on(db)
    fake.replies["claude_api"] = [_reply(AFCI_ITEM)]
    _run(call, elec["id"])
    detail = call("GET", f"{API}/estimates/{elec['id']}/detail").json()
    assert detail["inspector"]["enabled"] is True and detail["inspector"]["ready"] is True
    assert detail["inspection_review"]["checklist"][0]["id"] == "afci"


def test_estimates_page_has_the_inspection_review_markers():
    js = (router.WEB_DIR / "estimates.js").read_text(encoding="utf-8")
    for needed in ("inspection-review", "inspection-run", "inspection-checklist", "inspection-zip",
                   "inspection-jurisdiction", "Run inspection review", "Add to estimate",
                   "Turn on the Inspector agent", "confirm with the building department",
                   "data-inspection-add", "data-inspection-item"):
        assert needed in js, needed
