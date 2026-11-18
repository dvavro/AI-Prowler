"""The Inspector agent: NEC edition, prompt, parsing, running and applying.

A fake provider stands in for Claude, Grok and Muse: no real API calls, no
token cost. The zip lookup is served from the seeded zip_cache: no network.
"""
import json
import urllib.error
import urllib.request
from datetime import date

import pytest

from estimator.agents import providers, roles
from estimator.context import RequestContext, personal_context
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import inspection_review as ir
from estimator.estimating import quick, service
from estimator.estimating.zip_lookup import nec_edition

CTX = personal_context()
OFFICE = RequestContext(user_id="olga", role="office")
NOW = "2026-11-18T10:00:00+00:00"
ON_DATE = date(2026, 11, 18)          # Florida is on the 2020 NEC that day
ELEC = {"outlets": 10, "switches": 4, "lights": 6, "gfci": 0}
ADDR = "1500 Shadow Pines Dr, New Smyrna Beach, FL 32168"


class FakeTextProvider:
    """Answers like Claude or Grok would. replies[provider] is a list of texts
    (or exceptions) used in order. ask_vision must never be called - the
    inspection review is text-only, no images."""

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

    def ask_vision(self, provider, system, user, images, model=""):
        raise AssertionError("the inspection review must use ask, not ask_vision")

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
SURGE_ITEM = {"id": "surge_protection", "description": "Whole-house surge protection device",
              "code_ref": "230.67", "status": "pass", "note": "surge protector priced"}


# ------------------------------------------------------------------ the role and the edition

def test_inspector_role_exists_starts_off_and_works_now(db):
    meta = roles.ROLES["inspector"]
    assert meta["label"] == "Inspector" and meta["works_now"] is True
    got = roles.get_role(db, "default", "inspector")
    assert got["provider"] == "off" and got["ready"] is False
    assert "inspector" in {r["role"] for r in roles.overview(db, "default")["roles"]}


def test_nec_edition_florida_switches_on_dec_31_2026():
    assert nec_edition("FL", date(2026, 6, 1)) == {"edition": "2020", "code": "FBC 8th Edition",
                                                   "note": "Florida Building Code 8th Edition adopts the 2020 NEC"
                                                           " until December 30, 2026."}
    assert nec_edition("FL", date(2026, 12, 30))["edition"] == "2020"
    assert nec_edition("FL", date(2026, 12, 31)) == {"edition": "2023", "code": "FBC 9th Edition",
                                                     "note": "Florida Building Code 9th Edition adopts the 2023 NEC"
                                                             " from December 31, 2026."}
    assert nec_edition("FL", date(2027, 1, 1))["edition"] == "2023"
    assert nec_edition("fl", "2026-11-18")["edition"] == "2020"          # lowercase and ISO strings work


def test_nec_edition_unknown_state_is_a_fallback():
    for state in ("GA", "TX", "", None):
        out = nec_edition(state)
        assert out["edition"] is None and out["code"] is None
        assert "not in the local table" in out["note"] and "AHJ" in out["note"]


# ------------------------------------------------------------------ the prompt and the parsing

def test_prompt_carries_answers_lines_jurisdiction_edition_and_reference(db, elec):
    system, user = ir.build_prompt(
        service.get_estimate(db, CTX, elec["id"]),
        {"zip": "32168", "city": "New Smyrna Beach", "state": "Florida", "state_abbr": "FL",
         "verified": True},
        nec_edition("FL", ON_DATE))
    assert "Outlets: 10" in user and "GFCI outlets: 0" in user       # the electrical answers
    assert "Outlets and plates" in user                               # the line items
    assert "New Smyrna Beach, Florida (FL)" in user                   # the jurisdiction
    assert "2020 NEC under FBC 8th Edition" in user                  # the NEC edition
    assert "permit application date" in user                          # how the edition was picked
    for ref in ("210.8", "230.67", "210.12", "110.26", "NFPA 72"):   # the reference requirements
        assert ref in user, ref
    assert "verify with the AHJ" in user and "verify with the AHJ" in system
    assert "ONLY one JSON object" in system


def test_reference_requirements_cover_the_residential_list():
    refs = {r["id"]: r for r in ir.REFERENCE_REQUIREMENTS}
    assert len(refs) == 18 and refs["gfci"]["code_ref"] == "210.8"
    assert refs["surge_protection"]["code_ref"] == "230.67"
    assert refs["kitchen_circuits"]["code_ref"] == "210.11(C)(1)"
    assert refs["wire_gauge"]["code_ref"].startswith("240.4")
    assert all(r["description"] and r["code_ref"] for r in ir.REFERENCE_REQUIREMENTS)


def test_parse_valid_review():
    out = ir.parse_review_response(_reply(GFCI_ITEM, AFCI_ITEM, SURGE_ITEM))
    assert [i["status"] for i in out] == ["missing", "flag", "pass"]
    assert out[0]["suggested_action"] == {"price_key": "el_gfci_ea", "quantity": 2, "unit": "ea",
                                          "description": "GFCI outlets"}
    assert "suggested_action" not in out[1]
    # code fences around the JSON are tolerated
    assert ir.parse_review_response("```json\n" + _reply(AFCI_ITEM) + "\n```")[0]["id"] == "afci"


@pytest.mark.parametrize("bad", ["not json", "", "{}", '{"checklist": []}', '{"checklist": "no"}',
                                 '{"checklist": [{"id": "x"}]}',
                                 '{"checklist": [{"id": "x", "description": "d", "code_ref": "1", "status": "ok"}]}',
                                 '{"checklist": [{"id": "x", "description": "d", "code_ref": "1", "status": "pass",'
                                 ' "suggested_action": {"quantity": 1}}]}',
                                 '{"checklist": [{"id": "x", "description": "d", "code_ref": "1", "status": "pass"},'
                                 ' {"id": "x", "description": "d2", "code_ref": "2", "status": "pass"}]}'])
def test_parse_rejects_bad_answers(bad):
    with pytest.raises(ir.InspectionReviewError):
        ir.parse_review_response(bad)


# ------------------------------------------------------------------ running

def test_run_review_stores_a_review(db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM, AFCI_ITEM)]
    out = ir.run_review(db, CTX, elec["id"], on_date=ON_DATE)
    assert out["zip_code"] == "32168" and out["status"] == "complete"
    assert out["jurisdiction"]["city"] == "New Smyrna Beach"
    assert out["jurisdiction"]["verified"] is True
    assert out["nec_edition"] == "2020"
    assert [i["id"] for i in out["checklist"]] == ["gfci", "afci"]
    assert ir.latest_review(db, "default", elec["id"])["id"] == out["id"]
    assert len(fake.calls) == 1 and fake.calls[0]["model"] == "claude-sonnet-5-5"
    assert fake.calls[0]["provider"] == "claude_api"


def test_run_review_logs_usage_and_the_ai_log(db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(AFCI_ITEM)]
    ir.run_review(db, CTX, elec["id"], on_date=ON_DATE)
    usage = db.execute("SELECT role, task_id, ok FROM agent_usage").fetchall()
    assert [(r["role"], r["task_id"], r["ok"]) for r in usage] == [("inspector", None, 1)]
    log = db.execute("SELECT role, purpose, estimate_id, ok FROM ai_log").fetchall()
    assert [(r["role"], r["purpose"], r["estimate_id"], r["ok"]) for r in log] == [
        ("inspector", "Inspection review", elec["id"], 1)]


def test_run_review_uses_the_backup_provider(db, elec, fake):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [RuntimeError("boom")]
    fake.replies["grok_api"] = [_reply(AFCI_ITEM)]
    out = ir.run_review(db, CTX, elec["id"], on_date=ON_DATE)
    assert out["checklist"][0]["id"] == "afci"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    assert sorted(r["ok"] for r in db.execute("SELECT ok FROM agent_usage")) == [0, 1]


def test_run_review_works_when_the_zip_lookup_is_unreachable(db, fake, monkeypatch):
    e = service.create_estimate(db, CTX, "Orlando job", address="9 Pine St, Orlando, FL 32801")
    e = quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])
    _on(db)
    fake.replies["claude_api"] = [_reply(AFCI_ITEM)]

    def down(url, timeout=None):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", down)
    out = ir.run_review(db, CTX, e["id"], on_date=ON_DATE)
    assert out["jurisdiction"]["verified"] is False and out["jurisdiction"]["city"] is None
    assert out["nec_edition"] is None and out["checklist"][0]["id"] == "afci"


def test_run_review_refuses_when_the_role_is_off(db, elec, fake):
    with pytest.raises(InvalidInput, match="off"):
        ir.run_review(db, CTX, elec["id"])


def test_run_review_refuses_when_the_provider_isnt_ready(db, elec, fake):
    _on(db)
    fake.keys["claude_api"] = False
    with pytest.raises(InvalidInput, match="can't run yet"):
        ir.run_review(db, CTX, elec["id"])


def test_run_review_refuses_a_non_electrical_estimate(db, fake):
    e = service.create_estimate(db, CTX, "Roof")
    e = quick.answer(db, CTX, e["id"], "roofing",
                     {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}, e["rev"])
    _on(db)
    with pytest.raises(InvalidInput, match="no electrical section"):
        ir.run_review(db, CTX, e["id"])


def test_run_review_refuses_without_a_zip(db, fake):
    e = service.create_estimate(db, CTX, "No address")
    e = quick.answer(db, CTX, e["id"], "electrical", ELEC, e["rev"])
    _on(db)
    with pytest.raises(InvalidInput, match="no zip code"):
        ir.run_review(db, CTX, e["id"])
    with pytest.raises(InvalidInput, match="isn't a zip code"):
        ir.run_review(db, CTX, e["id"], zip_code="123")


def test_run_review_refuses_when_the_budget_is_used_up(db, elec, fake):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0}, confirm=True)
    with pytest.raises(ir.InspectionReviewError, match="budget"):
        ir.run_review(db, CTX, elec["id"], on_date=ON_DATE)


def test_run_review_requires_an_edit_role(db, elec, fake):
    _on(db)
    with pytest.raises(PermissionDenied):
        ir.run_review(db, OFFICE, elec["id"], on_date=ON_DATE)


def test_run_review_with_an_unusable_answer_logs_the_failure(db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = ["not json"]
    with pytest.raises(ir.InspectionReviewError, match="didn't answer with JSON"):
        ir.run_review(db, CTX, elec["id"], on_date=ON_DATE)
    assert ir.latest_review(db, "default", elec["id"]) is None      # no partial review stored
    row = db.execute("SELECT ok, error FROM ai_log").fetchone()
    assert row["ok"] == 0 and "JSON" in row["error"]


def test_inspector_setting(db, fake):
    assert ir.inspector_setting(db, "default")["enabled"] is False
    _on(db)
    s = ir.inspector_setting(db, "default")
    assert s["enabled"] is True and s["provider"] == "claude_api" and s["ready"] is True
    assert s["provider_label"] == "Claude API key" and s["why_not"] == ""


# ------------------------------------------------------------------ applying

def _reviewed(db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply(GFCI_ITEM, AFCI_ITEM)]
    return ir.run_review(db, CTX, elec["id"], on_date=ON_DATE)


def test_apply_adds_the_suggested_item_as_a_hand_line(db, elec, fake):
    review = _reviewed(db, elec, fake)
    out = ir.apply_item(db, CTX, elec["id"], review["id"], "gfci", elec["rev"])
    custom = next(s for s in out["sections"] if s["module_id"] == "custom")
    line = next(ln for ln in custom["lines"] if ln["price_key"] == "el_gfci_ea")
    assert line["description"] == "GFCI outlets" and line["quantity"] == "2" and line["unit"] == "ea"


def test_an_applied_line_survives_a_re_price(db, elec, fake):
    review = _reviewed(db, elec, fake)
    after = ir.apply_item(db, CTX, elec["id"], review["id"], "gfci", elec["rev"])
    repriced = quick.answer(db, CTX, elec["id"], "electrical", ELEC, after["rev"])
    custom = next(s for s in repriced["sections"] if s["module_id"] == "custom")
    assert any(ln["price_key"] == "el_gfci_ea" for ln in custom["lines"])


def test_apply_refuses_an_unknown_price_key(db, elec, fake):
    _on(db)
    fake.replies["claude_api"] = [_reply({**GFCI_ITEM, "suggested_action": {"price_key": "el_nope_ea"}})]
    review = ir.run_review(db, CTX, elec["id"], on_date=ON_DATE)
    with pytest.raises(NotFound, match="el_nope_ea"):
        ir.apply_item(db, CTX, elec["id"], review["id"], "gfci", elec["rev"])


def test_apply_refuses_an_item_with_no_suggestion(db, elec, fake):
    review = _reviewed(db, elec, fake)
    with pytest.raises(InvalidInput, match="no item to add"):
        ir.apply_item(db, CTX, elec["id"], review["id"], "afci", elec["rev"])
    with pytest.raises(NotFound, match="isn't in review"):
        ir.apply_item(db, CTX, elec["id"], review["id"], "nope", elec["rev"])


def test_mcp_tool_runs_a_review(db, elec, fake):
    from estimator.mcp_tools import est_tools as t

    _on(db)
    fake.replies["claude_api"] = [_reply(AFCI_ITEM)]
    out = json.loads(t.est_inspection_review(elec["id"]))
    assert out["checklist"][0]["id"] == "afci" and out["zip_code"] == "32168"
